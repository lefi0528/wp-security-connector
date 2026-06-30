<?php

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit; // Acces direct interdit
}

/**
 * Lecture sécurisée des fichiers WordPress.
 *
 * RÈGLE DE SÉCURITÉ :
 * - Lecture seule. Jamais d'écriture, d'include, d'eval, ou d'exec.
 * - Tous les chemins sont normalisés et vérifiés contre ABSPATH.
 * - Aucun fichier en dehors de ABSPATH ne peut être lu.
 */
class GENISECO_File_Manager
{
    private const MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024; // 5 Mo — au-delà, on retourne juste les métadonnées
    // Dossiers régénérables / non-source : exclus du scan. Le cache contient du HTML
    // généré (scripts externes, iframes d'embed légitimes), pas un vecteur de
    // persistance — il est régénéré de toute façon. Réduit massivement les faux positifs.
    private const EXCLUDED_DIRS = ['.git', 'node_modules', '.svn', 'cache', 'upgrade'];

    // Fichiers de SECRETS jamais transmis au SaaS (M-FILE-1). Le service de scan
    // ne doit jamais recevoir les credentials DB / clés privées du client (fuite de
    // secret + risque GDPR). Défense en profondeur contre la lecture arbitraire (B2).
    // Basenames exacts à exclure totalement de la liste ET de la lecture.
    private const EXCLUDED_FILES = ['.env', '.htpasswd', 'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519'];
    // Extensions de secrets (clés/certs) exclues totalement.
    private const EXCLUDED_EXTENSIONS = ['key', 'pem', 'p12', 'pfx', 'crt', 'ppk', 'asc'];

    /** True si le fichier contient des secrets et ne doit jamais sortir du site. */
    private function is_secret_file(string $basename): bool
    {
        if (in_array($basename, self::EXCLUDED_FILES, true)) {
            return true;
        }
        if (str_starts_with($basename, '.env')) { // .env.local, .env.production, …
            return true;
        }
        $ext = strtolower(pathinfo($basename, PATHINFO_EXTENSION));
        return in_array($ext, self::EXCLUDED_EXTENSIONS, true);
    }

    /**
     * Liste récursive des fichiers sous ABSPATH.
     *
     * @return array<array{path: string, size: int, mtime: int, hash: string, md5: string}>
     */
    public function list_files(string $relative_root = ''): array
    {
        $base = realpath(ABSPATH);
        if ($base === false) {
            return [];
        }

        $root = $relative_root
            ? $this->safe_resolve($relative_root)
            : $base;

        if ($root === null || !is_dir($root)) {
            return [];
        }

        $files = [];
        $iterator = new RecursiveIteratorIterator(
            new RecursiveCallbackFilterIterator(
                new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
                fn(SplFileInfo $f): bool => !in_array($f->getFilename(), self::EXCLUDED_DIRS, true)
            )
        );

        foreach ($iterator as $file) {
            /** @var SplFileInfo $file */
            if (!$file->isFile()) {
                continue;
            }

            $real = realpath($file->getPathname());
            // PATH-1 : exiger une frontière de séparateur, sinon un répertoire frère
            // « ABSPATH-evil » passerait le test str_starts_with.
            if ($real === false || !$this->is_within_base($real, $base)) {
                // Path traversal attempt
                continue;
            }

            // M-FILE-1 : ne jamais lister les fichiers de secrets.
            if ($this->is_secret_file($file->getFilename())) {
                continue;
            }

            // hash sha256 : identité de contenu (scans incrémentaux, futur).
            // md5 : permet au scanner de comparer aux checksums officiels
            // wordpress.org (qui sont en MD5) SANS télécharger le fichier core →
            // les fichiers core propres sont vérifiés par hash et jamais transférés.
            $files[] = [
                'path'  => substr($real, strlen($base) + 1),
                'size'  => $file->getSize(),
                'mtime' => $file->getMTime(),
                'hash'  => hash_file('sha256', $real) ?: '',
                'md5'   => hash_file('md5', $real) ?: '',
            ];
        }

        return $files;
    }

    /**
     * Retourne le contenu brut d'un fichier.
     * Retourne null si le chemin est invalide ou hors de ABSPATH.
     */
    public function read_file(string $relative_path): ?string
    {
        $real = $this->safe_resolve($relative_path);
        if ($real === null || !is_file($real)) {
            return null;
        }

        $basename = basename($real);

        // M-FILE-1 : refuser totalement les fichiers de secrets (défense en
        // profondeur — vaut même si le chemin a été falsifié, cf. B2).
        if ($this->is_secret_file($basename)) {
            return null;
        }

        $size = filesize($real);
        if ($size === false || $size > self::MAX_FILE_SIZE_BYTES) {
            return null; // Trop gros — le scanner demandera les métadonnées uniquement
        }

        $content = file_get_contents($real);
        if ($content === false) {
            return null;
        }

        // wp-config.php : on garde le scan (cible fréquente d'injection) mais on
        // CAVIARDE les valeurs sensibles (credentials DB, clés, salts). Le scanner
        // voit toujours un éventuel code malveillant inséré, jamais les secrets.
        if ($basename === 'wp-config.php' || str_starts_with($basename, 'wp-config')) {
            $content = $this->redact_wp_config($content);
        }

        return $content;
    }

    /** Masque les valeurs des constantes sensibles de wp-config.php. */
    private function redact_wp_config(string $content): string
    {
        $constants = 'DB_NAME|DB_USER|DB_PASSWORD|DB_HOST|DB_CHARSET|DB_COLLATE'
            . '|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY'
            . '|AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT';

        // define('DB_PASSWORD', 'secret') → define('DB_PASSWORD', '[REDACTED]')
        // La valeur est matchée comme une chaîne PHP quotée complète, en gérant les
        // guillemets ÉCHAPPÉS (\' \") : robuste même si un salt WordPress contient
        // des guillemets ou la séquence ');'. Aucune fuite partielle possible.
        $redacted = preg_replace(
            "/(define\s*\(\s*['\"](?:{$constants})['\"]\s*,\s*)(['\"])(?:\\\\.|(?!\\2).)*\\2/is",
            "$1'[REDACTED]'",
            $content
        );

        return $redacted ?? $content;
    }

    /**
     * Résout un chemin relatif contre ABSPATH et vérifie qu'il reste dans ABSPATH.
     * Retourne null si la résolution échoue ou si le chemin sort de ABSPATH.
     */
    private function safe_resolve(string $relative_path): ?string
    {
        $base = realpath(ABSPATH);
        if ($base === false) {
            return null;
        }

        // Interdit les composants dangereux même avant realpath
        if (str_contains($relative_path, "\0")) {
            return null;
        }

        $full = $base . DIRECTORY_SEPARATOR . ltrim($relative_path, '/\\');
        $real = realpath($full);

        if ($real === false || !$this->is_within_base($real, $base)) {
            return null; // Path traversal
        }

        return $real;
    }

    /**
     * Vérifie que $real est strictement contenu dans $base, avec frontière de
     * séparateur (PATH-1) : « /var/www/html » ne doit pas matcher « /var/www/html-evil ».
     */
    private function is_within_base(string $real, string $base): bool
    {
        return $real === $base
            || str_starts_with($real, $base . DIRECTORY_SEPARATOR);
    }
}
