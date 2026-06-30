<?php

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit; // Acces direct interdit
}

/**
 * Gestionnaire de backup — Phase 2.
 *
 * RÈGLES DE SÉCURITÉ (CLAUDE.md) :
 * - Backup OBLIGATOIRE avant toute action de nettoyage.
 * - Jamais de shell_exec / exec / system.
 * - Le répertoire de backup est protégé contre l'accès HTTP (.htaccess Deny).
 * - Exportation DB via wpdb uniquement (pas de mysqldump shell).
 * - Retourne un manifest_hash vérifiable par le SaaS avant d'autoriser les actions.
 */
class WSC_Backup_Manager
{
    private const BACKUP_DIR  = '.wsc-quarantine/backups';
    private const DB_TABLES   = ['options', 'posts', 'postmeta', 'users', 'usermeta', 'term_relationships', 'term_taxonomy', 'terms'];

    // ─── Public API ───────────────────────────────────────────────────────────

    /**
     * Crée un backup : manifest fichiers + dump DB des tables critiques.
     *
     * @param string[] $file_paths Chemins relatifs des fichiers concernés par le nettoyage
     * @return array{backupId:string,manifestHash:string,dbTablesExported:string[],fileCount:int}|null
     */
    public function create_backup(array $file_paths): array|null
    {
        $backup_dir = $this->ensure_backup_dir();
        if ($backup_dir === null) {
            return null;
        }

        $backup_id = date('Ymd-His') . '-' . bin2hex(random_bytes(4));
        $slot      = $backup_dir . DIRECTORY_SEPARATOR . $backup_id;

        if (!wp_mkdir_p($slot)) {
            return null;
        }

        // 1. Manifest des fichiers à modifier (chemin + hash avant action)
        $manifest = $this->build_file_manifest($file_paths);
        $manifest_json = json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if ($manifest_json === false) {
            return null;
        }

        if (file_put_contents($slot . '/file-manifest.json', $manifest_json, LOCK_EX) === false) {
            return null;
        }

        // 2. Export DB des tables critiques via wpdb
        $exported_tables = $this->export_db($slot);

        // 3. Hash du manifest (vérifiable par le SaaS)
        $manifest_hash = hash('sha256', $manifest_json);

        // 4. Fichier de métadonnées du backup
        $meta = json_encode([
            'backupId'        => $backup_id,
            'createdAt'       => time(),
            'manifestHash'    => $manifest_hash,
            'fileCount'       => count($manifest),
            'dbTablesExported' => $exported_tables,
            'wpVersion'       => get_bloginfo('version'),
            'pluginVersion'   => WSC_VERSION,
        ], JSON_PRETTY_PRINT);

        if ($meta !== false) {
            file_put_contents($slot . '/meta.json', $meta, LOCK_EX);
        }

        return [
            'backupId'         => $backup_id,
            'manifestHash'     => $manifest_hash,
            'dbTablesExported' => $exported_tables,
            'fileCount'        => count($manifest),
        ];
    }

    /**
     * Vérifie qu'un backup existe et retourne son hash de manifest.
     * Utilisé par le SaaS pour confirmer le backup avant d'exécuter des actions.
     */
    public function verify_backup(string $backup_id): array|null
    {
        $backup_dir = $this->backup_dir_path();
        if ($backup_dir === null) {
            return null;
        }

        // Valide le format du backup_id (anti path-traversal)
        if (!preg_match('/^\d{8}-\d{6}-[0-9a-f]{8}$/', $backup_id)) {
            return null;
        }

        $meta_file = $backup_dir . DIRECTORY_SEPARATOR . $backup_id . '/meta.json';
        if (!is_file($meta_file)) {
            return null;
        }

        $meta_raw = file_get_contents($meta_file);
        if ($meta_raw === false) {
            return null;
        }

        $meta = json_decode($meta_raw, true);
        if (!is_array($meta)) {
            return null;
        }

        return [
            'backupId'      => $meta['backupId'] ?? $backup_id,
            'manifestHash'  => $meta['manifestHash'] ?? '',
            'fileCount'     => $meta['fileCount'] ?? 0,
            'createdAt'     => $meta['createdAt'] ?? 0,
        ];
    }

    // ─── Private helpers ──────────────────────────────────────────────────────

    /**
     * Construit le manifest des fichiers : chemin relatif + hash SHA-256 actuel.
     *
     * @param string[] $file_paths
     * @return array<array{path:string,hash:string,size:int}>
     */
    private function build_file_manifest(array $file_paths): array
    {
        $base     = rtrim((string) realpath(ABSPATH), '/\\');
        $manifest = [];

        foreach ($file_paths as $relative_path) {
            if (str_contains($relative_path, "\0")) {
                continue;
            }

            $full = $base . DIRECTORY_SEPARATOR . ltrim($relative_path, '/\\');
            $real = realpath($full);

            if ($real === false || !str_starts_with($real, $base) || !is_file($real)) {
                continue;
            }

            $manifest[] = [
                'path' => $relative_path,
                'hash' => hash_file('sha256', $real) ?: '',
                'size' => filesize($real) ?: 0,
            ];
        }

        return $manifest;
    }

    /**
     * Exporte les tables critiques de la DB via wpdb (jamais de shell_exec).
     *
     * @return string[] Liste des tables exportées avec succès
     */
    private function export_db(string $backup_slot): array
    {
        global $wpdb;

        $exported   = [];
        $table_prefix = $wpdb->prefix;

        foreach (self::DB_TABLES as $table_suffix) {
            $table = $table_prefix . $table_suffix;

            // Vérifie que la table existe
            $exists = $wpdb->get_var(
                $wpdb->prepare('SHOW TABLES LIKE %s', $table)
            );
            if ($exists === null) {
                continue;
            }

            // $table = $wpdb->prefix + un suffixe issu de la whitelist self::DB_TABLES (constante,
            // jamais d'entrée utilisateur). Un identifiant de table ne peut pas être lié via
            // prepare() (le placeholder le quoterait) → interpolation sûre, annotée pour PHPCS.
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- identifiant de table de confiance.
            $rows = $wpdb->get_results("SELECT * FROM `{$table}`", ARRAY_A);
            if ($rows === null) {
                continue;
            }

            $sql  = "-- Table: {$table}\n";
            $sql .= "-- Exported: " . date('Y-m-d H:i:s') . "\n\n";

            if (empty($rows)) {
                $sql .= "-- (empty table)\n";
            } else {
                $columns = array_keys($rows[0]);
                $cols_escaped = implode('`, `', array_map('esc_sql', $columns));

                foreach ($rows as $row) {
                    $values = array_map(
                        fn($v) => $v === null ? 'NULL' : "'" . esc_sql((string) $v) . "'",
                        array_values($row)
                    );
                    $sql .= "INSERT INTO `{$table}` (`{$cols_escaped}`) VALUES (" . implode(', ', $values) . ");\n";
                }
            }

            $file = $backup_slot . '/' . sanitize_file_name($table) . '.sql';
            if (file_put_contents($file, $sql, LOCK_EX) !== false) {
                $exported[] = $table;
            }
        }

        return $exported;
    }

    /** Retourne le chemin absolu du répertoire de backups. */
    private function backup_dir_path(): ?string
    {
        $dir = WP_CONTENT_DIR . DIRECTORY_SEPARATOR . self::BACKUP_DIR;
        return is_dir($dir) ? $dir : null;
    }

    /** Crée le répertoire de backups avec protection HTTP. Retourne le chemin ou null. */
    private function ensure_backup_dir(): ?string
    {
        $dir = WP_CONTENT_DIR . DIRECTORY_SEPARATOR . self::BACKUP_DIR;

        if (!is_dir($dir)) {
            if (!wp_mkdir_p($dir)) {
                return null;
            }
            file_put_contents($dir . '/.htaccess', "Deny from all\nOptions -Indexes\n");
            file_put_contents($dir . '/index.php', "<?php // Silence is golden.\n");
        }

        return $dir;
    }
}
