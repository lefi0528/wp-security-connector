<?php

declare(strict_types=1);

/**
 * Gestionnaire de quarantaine — Phase 2.
 *
 * RÈGLES DE SÉCURITÉ :
 * - Ne supprime JAMAIS de fichiers. La quarantaine = déplacement réversible.
 * - Vérifie le hash du fichier avant toute action (backup via checksum).
 * - Protège le répertoire de quarantaine contre l'accès HTTP.
 * - Toutes les résolutions de chemin passent par safe_resolve().
 * - Nonce à usage unique vérifié par HMAC avant toute écriture.
 */
class WSC_Quarantine_Manager
{
    /** Répertoire de quarantaine, relatif à WP_CONTENT_DIR */
    private const QUARANTINE_DIR = '.wsc-quarantine';

    public function __construct(
        private readonly WSC_Hmac_Auth $auth,
        private readonly WSC_File_Manager $files,
    ) {}

    // ─── Public API ───────────────────────────────────────────────────────────

    /**
     * Déplace un fichier hors du webroot vers le répertoire de quarantaine.
     *
     * @param string $relative_path Chemin relatif depuis ABSPATH
     * @param string $action_id     Identifiant unique de l'action (depuis le SaaS)
     * @param string $expected_hash SHA-256 du fichier attendu (vérification avant déplacement)
     * @return array{quarantinedPath:string,originalHash:string,verified:bool}|null
     */
    public function quarantine(string $relative_path, string $action_id, string $expected_hash): array|null
    {
        $base = $this->abspath();
        $real = $this->safe_resolve($relative_path);
        if ($real === null || !is_file($real)) {
            return null;
        }

        // Vérification du hash avant déplacement (backup vérifié par checksum)
        $actual_hash = hash_file('sha256', $real);
        $hash_ok = $actual_hash !== false && hash_equals($actual_hash, $expected_hash);

        $quarantine_dir = $this->ensure_quarantine_dir();
        if ($quarantine_dir === null) {
            return null;
        }

        $safe_name    = $this->safe_quarantine_name($relative_path, $action_id);
        $quarantine_to = $quarantine_dir . DIRECTORY_SEPARATOR . $safe_name;

        if (!rename($real, $quarantine_to)) {
            return null;
        }

        $quarantine_relative = 'wp-content/' . self::QUARANTINE_DIR . '/' . $safe_name;

        return [
            'quarantinedPath' => $quarantine_relative,
            'originalHash'    => $actual_hash ?: '',
            'verified'        => $hash_ok,
        ];
    }

    /**
     * Remplace un fichier infecté par un contenu propre fourni en base64.
     * Le fichier infecté est mis en quarantaine AVANT le remplacement.
     *
     * @param string $relative_path   Chemin relatif depuis ABSPATH
     * @param string $action_id       Identifiant unique de l'action
     * @param string $expected_hash   Hash SHA-256 du fichier actuel (vérification)
     * @param string $new_content_b64 Contenu propre encodé en base64
     * @param string $wp_version      Version WordPress du remplacement (pour le log)
     * @return array{quarantinedPath:string,newHash:string,replacedWithVersion:string}|null
     */
    public function replace(
        string $relative_path,
        string $action_id,
        string $expected_hash,
        string $new_content_b64,
        string $wp_version,
    ): array|null {
        $base = $this->abspath();
        $real = $this->safe_resolve($relative_path);
        if ($real === null || !is_file($real)) {
            return null;
        }

        // INVARIANT DE SÉCURITÉ : un fichier core ne doit JAMAIS finir manquant.
        // On ne met l'original en quarantaine qu'APRÈS avoir un remplacement
        // valide écrit et vérifié sur disque, et on restaure en cas d'échec tardif.

        // 1. Décode et valide le contenu propre AVANT de toucher à l'original.
        $new_content = base64_decode($new_content_b64, true);
        if ($new_content === false || $new_content === '') {
            return null; // Pas de remplacement valide — abandon, original intact
        }

        // M-REPLACE-1 : le contenu de remplacement doit correspondre EXACTEMENT au
        // fichier core OFFICIEL (checksum api.wordpress.org). Sans ça, l'ancien code
        // ne faisait qu'un hash tautologique (contenu vs lui-même) → un appelant avec
        // HMAC + nonce compromis pouvait écrire du PHP arbitraire = RCE. La source du
        // checksum est api.wordpress.org (jamais l'appelant). Restreint de fait /replace
        // aux fichiers core vérifiables : un chemin non-core → md5 officiel null → refus.
        $official_md5 = $this->official_core_md5($wp_version, $relative_path);
        if ($official_md5 === null || !hash_equals($official_md5, md5($new_content))) {
            return null; // Contenu non conforme au core officiel — abandon, original intact
        }

        $expected_new_hash = hash('sha256', $new_content);

        // 2. Écrit le contenu propre dans un fichier temporaire (même répertoire
        //    → rename atomique sur le même volume), puis vérifie son intégrité.
        $tmp = $real . '.wsc-tmp-' . substr($action_id, 0, 12);
        if (file_put_contents($tmp, $new_content, LOCK_EX) === false) {
            return null; // Écriture impossible — abandon, original intact
        }
        $tmp_hash = hash_file('sha256', $tmp);
        if ($tmp_hash === false || !hash_equals($expected_new_hash, $tmp_hash)) {
            @unlink($tmp);
            return null; // Temp corrompu — abandon, original intact
        }

        // 3. Maintenant seulement : quarantaine de l'original (remplacement prêt).
        $quarantine_result = $this->quarantine($relative_path, $action_id, $expected_hash);
        if ($quarantine_result === null) {
            @unlink($tmp);
            return null; // Quarantaine impossible — abandon, original intact
        }

        // 4. Met le fichier propre à la place de l'original.
        if (!rename($tmp, $real)) {
            // Échec APRÈS quarantaine → ROLLBACK : restaure l'original pour ne
            // jamais laisser un fichier core manquant (cause de WP cassé).
            $q_abs = $base . DIRECTORY_SEPARATOR
                   . str_replace('/', DIRECTORY_SEPARATOR, $quarantine_result['quarantinedPath']);
            @rename($q_abs, $real);
            @unlink($tmp);
            return null;
        }

        return [
            'quarantinedPath'    => $quarantine_result['quarantinedPath'],
            'newHash'            => $expected_new_hash,
            'replacedWithVersion' => $wp_version,
        ];
    }

    /**
     * Restaure un fichier depuis la quarantaine vers son emplacement d'origine.
     * Utilisé pour annuler une action de nettoyage.
     *
     * @param string $relative_path     Chemin d'origine (relatif à ABSPATH)
     * @param string $quarantined_path  Chemin relatif du fichier en quarantaine (relatif à ABSPATH)
     */
    public function rollback(string $relative_path, string $quarantined_path): array|null
    {
        $base = $this->abspath();

        // Vérifie que le fichier en quarantaine est bien dans notre répertoire de quarantaine
        $qreal = realpath($base . DIRECTORY_SEPARATOR . ltrim($quarantined_path, '/\\'));
        $qdir  = realpath(WP_CONTENT_DIR . DIRECTORY_SEPARATOR . self::QUARANTINE_DIR);

        if ($qreal === false || $qdir === false) {
            return null;
        }
        if (!$this->is_within($qreal, $qdir)) {
            return null; // Path traversal — le fichier n'est pas dans notre quarantaine
        }
        if (!is_file($qreal)) {
            return null;
        }

        $dest = $base . DIRECTORY_SEPARATOR . ltrim($relative_path, '/\\');
        $dest_dir = dirname($dest);
        if (!is_dir($dest_dir)) {
            return null;
        }

        // Vérifie que la destination reste dans ABSPATH (frontière de séparateur incluse)
        $dest_dir_real = realpath($dest_dir) ?: '';
        if (!$this->is_within($dest_dir_real, $base)) {
            return null;
        }

        if (!rename($qreal, $dest)) {
            return null;
        }

        return ['restoredPath' => $relative_path];
    }

    // ─── Nonce verification ───────────────────────────────────────────────────

    /**
     * Vérifie le nonce de type write (anti-replay pour les endpoints d'écriture).
     *
     * Format reçu dans X-WSC-Write-Nonce : "{actionId}:{nonce_hmac}"
     * Nonce = HMAC-SHA256(hmacSecret, "write-nonce:{actionId}:{timestamp}")
     *
     * @param string $header_value  Valeur de X-WSC-Write-Nonce
     * @param string $timestamp     Valeur de X-WSC-Timestamp (epoch string)
     * @param string $hmac_secret   Clé HMAC en hexadécimal (64 chars)
     */
    public function verify_write_nonce(
        string $header_value,
        string $timestamp,
        string $hmac_secret,
    ): bool {
        // Format : "actionId:nonceHex"
        $parts = explode(':', $header_value, 2);
        if (count($parts) !== 2) {
            return false;
        }
        [$action_id, $nonce_received] = $parts;

        // Vérification temporelle (HMAC-7 : alignée sur la fenêtre de signature, 5 min).
        $ts_int = (int) $timestamp;
        if (abs(time() - $ts_int) > 300) {
            return false;
        }

        $expected = hash_hmac(
            'sha256',
            "write-nonce:{$action_id}:{$ts_int}",
            hex2bin($hmac_secret) ?: '',
        );

        if (!hash_equals($expected, $nonce_received)) {
            return false;
        }

        // Anti-replay via transient WP. HMAC-6 : clé = hash complet du nonce (pas un
        // préfixe tronqué de 20 chars, qui exposait à des collisions de préfixe).
        $transient_key = 'wsc_nonce_' . hash('sha256', $nonce_received);
        if (get_transient($transient_key) !== false) {
            return false; // Nonce déjà utilisé
        }
        set_transient($transient_key, 1, 300);

        return true;
    }

    // ─── Private helpers ──────────────────────────────────────────────────────

    /**
     * MD5 OFFICIEL d'un fichier core, depuis api.wordpress.org (mis en cache 1 jour).
     * La source du checksum est TOUJOURS api.wordpress.org — jamais l'appelant — pour
     * que /replace ne puisse écrire que le contenu core authentique (M-REPLACE-1).
     * Retourne null si le fichier n'est pas un fichier core officiel, ou si l'API est
     * injoignable (fail-closed : pas de checksum vérifiable → pas de remplacement).
     */
    private function official_core_md5(string $wp_version, string $relative_path): ?string
    {
        $version = preg_replace('/[^0-9.]/', '', $wp_version) ?? '';
        if ($version === '') {
            return null;
        }

        $cache_key = 'wsc_core_sums_' . $version;
        $sums = get_transient($cache_key);

        if (!is_array($sums)) {
            $url  = 'https://api.wordpress.org/core/checksums/1.0/?version='
                  . rawurlencode($version) . '&locale=en_US';
            $resp = wp_remote_get($url, ['timeout' => 15]);
            if (is_wp_error($resp) || (int) wp_remote_retrieve_response_code($resp) !== 200) {
                return null; // fail-closed
            }
            $json = json_decode((string) wp_remote_retrieve_body($resp), true);
            if (!is_array($json) || !isset($json['checksums']) || !is_array($json['checksums'])) {
                return null;
            }
            $checksums = $json['checksums'];
            $sums = (isset($checksums['en_US']) && is_array($checksums['en_US']))
                ? $checksums['en_US']
                : $checksums;
            if (!is_array($sums)) {
                return null;
            }
            set_transient($cache_key, $sums, DAY_IN_SECONDS);
        }

        $norm = ltrim(str_replace('\\', '/', $relative_path), '/');
        $md5  = $sums[$norm] ?? null;

        return is_string($md5) ? $md5 : null;
    }

    /** Génère un nom sûr pour le fichier en quarantaine */
    private function safe_quarantine_name(string $relative_path, string $action_id): string
    {
        // Remplace tout caractère non alphanumérique (sauf .) par un underscore
        $safe = preg_replace('/[^a-zA-Z0-9._-]/', '_', $relative_path) ?? 'file';
        $ts   = time();
        // actionId tronqué à 12 chars pour l'identification
        return $safe . '.' . substr($action_id, 0, 12) . '.' . $ts . '.quarantined';
    }

    /** Résout un chemin relatif sécurisé contre ABSPATH. Retourne null si path traversal. */
    private function safe_resolve(string $relative_path): ?string
    {
        $base = $this->abspath();
        if (str_contains($relative_path, "\0")) {
            return null;
        }
        $full = $base . DIRECTORY_SEPARATOR . ltrim($relative_path, '/\\');
        $real = realpath($full);
        if ($real === false || !$this->is_within($real, $base)) {
            return null;
        }
        return $real;
    }

    /** Confinement strict avec frontière de séparateur (PATH-1) : /a/b ne matche pas /a/b-evil. */
    private function is_within(string $real, string $base): bool
    {
        return $real === $base || str_starts_with($real, $base . DIRECTORY_SEPARATOR);
    }

    private function abspath(): string
    {
        return rtrim((string) realpath(ABSPATH), '/\\');
    }

    /**
     * Crée le répertoire de quarantaine avec protection HTTP si nécessaire.
     * Retourne le chemin absolu ou null en cas d'échec.
     */
    private function ensure_quarantine_dir(): ?string
    {
        $dir = WP_CONTENT_DIR . DIRECTORY_SEPARATOR . self::QUARANTINE_DIR;

        if (!is_dir($dir)) {
            if (!wp_mkdir_p($dir)) {
                return null;
            }
            // Protège contre l'accès HTTP direct
            file_put_contents($dir . '/.htaccess', "Deny from all\n");
            file_put_contents($dir . '/index.php', "<?php // Silence is golden.\n");
        }

        return $dir;
    }
}
