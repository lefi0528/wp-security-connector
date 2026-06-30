<?php

declare(strict_types=1);

/**
 * Enregistrement des endpoints REST WordPress.
 * Namespace : /wp-json/wsc/v1/
 *
 * Phase 1 (lecture seule) :
 *   GET /info       — version WP, plugins actifs, thème
 *   GET /files      — liste récursive des fichiers avec hash SHA-256
 *   GET /file       — contenu d'un fichier (param: path)
 *   GET /db         — analyse BDD lecture seule (options/users/cron/posts suspects, pré-filtrés)
 *
 * Phase 2 (écriture, nonce à usage unique obligatoire) :
 *   POST /backup     — crée un backup fichiers + DB avant toute action (OBLIGATOIRE)
 *   POST /quarantine — déplace un fichier en quarantaine réversible
 *   POST /replace    — met en quarantaine + remplace par version officielle
 *   POST /rollback   — restaure un fichier depuis la quarantaine
 *   GET  /backup/verify — vérifie qu'un backup existe et retourne son hash
 */
class WSC_Api_Server
{
    private const NAMESPACE = 'wsc/v1';

    public function __construct(
        private readonly WSC_Hmac_Auth $auth,
        private readonly WSC_File_Manager $files,
        private readonly ?WSC_Quarantine_Manager $quarantine = null,
        private readonly ?WSC_Backup_Manager $backup = null,
        private readonly ?WSC_Db_Scanner $db = null,
    ) {}

    public function register_routes(): void
    {
        add_action('rest_api_init', function () {
            // ── Phase 1 : lecture seule ───────────────────────────────────────
            register_rest_route(self::NAMESPACE, '/info', [
                'methods'             => WP_REST_Server::READABLE,
                'callback'            => [$this, 'handle_info'],
                'permission_callback' => [$this, 'check_hmac'],
            ]);

            register_rest_route(self::NAMESPACE, '/files', [
                'methods'             => WP_REST_Server::READABLE,
                'callback'            => [$this, 'handle_files'],
                'permission_callback' => [$this, 'check_hmac'],
                'args'                => [
                    'root' => [
                        'type'              => 'string',
                        'default'           => '',
                        'sanitize_callback' => 'sanitize_text_field',
                    ],
                ],
            ]);

            register_rest_route(self::NAMESPACE, '/file', [
                'methods'             => WP_REST_Server::READABLE,
                'callback'            => [$this, 'handle_file'],
                'permission_callback' => [$this, 'check_hmac'],
                'args'                => [
                    'path' => [
                        'type'              => 'string',
                        'required'          => true,
                        'sanitize_callback' => 'sanitize_text_field',
                    ],
                ],
            ]);

            // Analyse BDD lecture seule (couche C). Pré-filtrée + caviardée côté plugin.
            if ($this->db !== null) {
                register_rest_route(self::NAMESPACE, '/db', [
                    'methods'             => WP_REST_Server::READABLE,
                    'callback'            => [$this, 'handle_db_scan'],
                    'permission_callback' => [$this, 'check_hmac'],
                ]);
            }

            // ── Phase 2 : backup + écriture (quarantaine réversible) ─────────
            if ($this->backup !== null) {
                register_rest_route(self::NAMESPACE, '/backup', [
                    'methods'             => WP_REST_Server::CREATABLE,
                    'callback'            => [$this, 'handle_backup'],
                    // M-HMAC-1 : /backup change l'état (crée des dumps) → anti-rejeu obligatoire.
                    'permission_callback' => [$this, 'check_hmac_no_replay'],
                ]);

                register_rest_route(self::NAMESPACE, '/backup/verify', [
                    'methods'             => WP_REST_Server::READABLE,
                    'callback'            => [$this, 'handle_backup_verify'],
                    'permission_callback' => [$this, 'check_hmac'],
                    'args'                => [
                        'backupId' => [
                            'type'              => 'string',
                            'required'          => true,
                            'sanitize_callback' => 'sanitize_text_field',
                        ],
                    ],
                ]);
            }

            if ($this->quarantine !== null) {
                register_rest_route(self::NAMESPACE, '/quarantine', [
                    'methods'             => WP_REST_Server::CREATABLE,
                    'callback'            => [$this, 'handle_quarantine'],
                    'permission_callback' => [$this, 'check_hmac_write'],
                ]);

                register_rest_route(self::NAMESPACE, '/replace', [
                    'methods'             => WP_REST_Server::CREATABLE,
                    'callback'            => [$this, 'handle_replace'],
                    'permission_callback' => [$this, 'check_hmac_write'],
                ]);

                register_rest_route(self::NAMESPACE, '/rollback', [
                    'methods'             => WP_REST_Server::CREATABLE,
                    'callback'            => [$this, 'handle_rollback'],
                    'permission_callback' => [$this, 'check_hmac_write'],
                ]);
            }
        });
    }

    // ─── Permission callbacks ─────────────────────────────────────────────────

    public function check_hmac(WP_REST_Request $request): bool|WP_Error
    {
        if (!$this->auth->verify($request)) {
            return new WP_Error('wsc_unauthorized', 'Signature HMAC invalide ou absente.', ['status' => 401]);
        }
        return true;
    }

    /**
     * HMAC + anti-rejeu par signature (M-HMAC-1). Pour les endpoints d'état sans
     * write-nonce (ex. /backup) : une requête signée capturée n'est utilisable qu'une fois.
     */
    public function check_hmac_no_replay(WP_REST_Request $request): bool|WP_Error
    {
        if (!$this->auth->verify_no_replay($request)) {
            return new WP_Error('wsc_unauthorized', 'Signature HMAC invalide, absente ou rejouée.', ['status' => 401]);
        }
        return true;
    }

    /**
     * Pour les endpoints d'écriture : HMAC + nonce à usage unique obligatoire.
     */
    public function check_hmac_write(WP_REST_Request $request): bool|WP_Error
    {
        if (!$this->auth->verify($request)) {
            return new WP_Error('wsc_unauthorized', 'Signature HMAC invalide.', ['status' => 401]);
        }

        $nonce_header = $request->get_header('X-WSC-Write-Nonce');
        $timestamp    = $request->get_header('X-WSC-Timestamp');
        $hmac_secret  = get_option('wsc_hmac_secret', '');

        if (!$nonce_header || !$timestamp || !$hmac_secret) {
            return new WP_Error('wsc_forbidden', 'Write-nonce manquant ou clé non configurée.', ['status' => 403]);
        }

        if ($this->quarantine === null || !$this->quarantine->verify_write_nonce($nonce_header, $timestamp, $hmac_secret)) {
            return new WP_Error('wsc_forbidden', 'Write-nonce invalide ou déjà utilisé.', ['status' => 403]);
        }

        return true;
    }

    // ─── Phase 1 handlers ────────────────────────────────────────────────────

    public function handle_info(WP_REST_Request $request): WP_REST_Response
    {
        $raw_plugins = get_option('active_plugins', []);
        $theme       = wp_get_theme();

        // Build plugin list with versions for WPScan CVE detection (Phase 3)
        $plugins_with_versions = [];
        foreach ((array) $raw_plugins as $plugin_file) {
            $slug  = explode('/', (string) $plugin_file)[0];
            $data  = function_exists('get_plugin_data')
                ? get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin_file, false, false)
                : [];
            $plugins_with_versions[] = [
                'slug'    => $slug,
                'file'    => $plugin_file,
                'version' => $data['Version'] ?? null,
                'name'    => $data['Name']    ?? $slug,
            ];
        }

        return new WP_REST_Response([
            'wp_version'              => get_bloginfo('version'),
            'php_version'             => PHP_VERSION,
            'active_plugins'          => array_values((array) $raw_plugins), // backward compat
            'active_plugins_extended' => $plugins_with_versions,
            'active_theme'            => [
                'name'    => $theme->get('Name'),
                'version' => $theme->get('Version'),
                'slug'    => get_stylesheet(),
            ],
            'site_url'                => get_site_url(),
            'abspath'                 => '', // Intentionnellement vide — chemins relatifs uniquement
            'plugin_version'          => WSC_VERSION,
        ], 200);
    }

    public function handle_files(WP_REST_Request $request): WP_REST_Response
    {
        $root  = $request->get_param('root') ?? '';
        $files = $this->files->list_files((string) $root);
        return new WP_REST_Response(['files' => $files, 'count' => count($files)], 200);
    }

    public function handle_file(WP_REST_Request $request): WP_REST_Response|WP_Error
    {
        $path    = $request->get_param('path');
        $content = $this->files->read_file((string) $path);

        if ($content === null) {
            return new WP_Error('wsc_not_found', 'Fichier introuvable ou inaccessible.', ['status' => 404]);
        }

        return new WP_REST_Response([
            'path'    => $path,
            'content' => base64_encode($content),
            'size'    => strlen($content),
        ], 200);
    }

    public function handle_db_scan(WP_REST_Request $request): WP_REST_Response|WP_Error
    {
        if ($this->db === null) {
            return new WP_Error('wsc_not_found', 'Analyse BDD non disponible.', ['status' => 404]);
        }
        return new WP_REST_Response($this->db->scan(), 200);
    }

    // ─── Phase 2 handlers ────────────────────────────────────────────────────

    public function handle_backup(WP_REST_Request $request): WP_REST_Response|WP_Error
    {
        $body       = json_decode($request->get_body(), true);
        $file_paths = $body['filePaths'] ?? [];

        if (!is_array($file_paths) || empty($file_paths)) {
            return new WP_Error('wsc_bad_request', 'filePaths (array) requis et non vide.', ['status' => 400]);
        }

        // Limite de sécurité : 500 fichiers max par backup
        if (count($file_paths) > 500) {
            return new WP_Error('wsc_bad_request', 'Trop de fichiers (max 500 par backup).', ['status' => 400]);
        }

        $result = $this->backup?->create_backup(array_map('sanitize_text_field', $file_paths));
        if ($result === null) {
            return new WP_Error('wsc_backup_failed', 'Impossible de créer le backup.', ['status' => 500]);
        }

        return new WP_REST_Response($result, 201);
    }

    public function handle_backup_verify(WP_REST_Request $request): WP_REST_Response|WP_Error
    {
        $backup_id = sanitize_text_field($request->get_param('backupId') ?? '');

        if (!$backup_id) {
            return new WP_Error('wsc_bad_request', 'backupId requis.', ['status' => 400]);
        }

        $result = $this->backup?->verify_backup($backup_id);
        if ($result === null) {
            return new WP_Error('wsc_not_found', 'Backup introuvable.', ['status' => 404]);
        }

        return new WP_REST_Response($result, 200);
    }

    public function handle_quarantine(WP_REST_Request $request): WP_REST_Response|WP_Error
    {
        $body = json_decode($request->get_body(), true);

        $file_path     = sanitize_text_field($body['filePath'] ?? '');
        $action_id     = sanitize_text_field($body['actionId'] ?? '');
        $expected_hash = sanitize_text_field($body['expectedHash'] ?? '');

        if (!$file_path || !$action_id || !$expected_hash) {
            return new WP_Error('wsc_bad_request', 'filePath, actionId et expectedHash requis.', ['status' => 400]);
        }

        $result = $this->quarantine?->quarantine($file_path, $action_id, $expected_hash);
        if ($result === null) {
            return new WP_Error('wsc_quarantine_failed', 'Impossible de mettre le fichier en quarantaine.', ['status' => 500]);
        }

        return new WP_REST_Response($result, 200);
    }

    public function handle_replace(WP_REST_Request $request): WP_REST_Response|WP_Error
    {
        $body = json_decode($request->get_body(), true);

        $file_path       = sanitize_text_field($body['filePath'] ?? '');
        $action_id       = sanitize_text_field($body['actionId'] ?? '');
        $expected_hash   = sanitize_text_field($body['expectedHash'] ?? '');
        $new_content_b64 = $body['newContentBase64'] ?? '';
        $wp_version      = sanitize_text_field($body['wpVersion'] ?? 'unknown');

        if (!$file_path || !$action_id || !$expected_hash || !$new_content_b64) {
            return new WP_Error('wsc_bad_request', 'Paramètres manquants.', ['status' => 400]);
        }

        $result = $this->quarantine?->replace($file_path, $action_id, $expected_hash, $new_content_b64, $wp_version);
        if ($result === null) {
            return new WP_Error('wsc_replace_failed', 'Impossible de remplacer le fichier.', ['status' => 500]);
        }

        return new WP_REST_Response($result, 200);
    }

    public function handle_rollback(WP_REST_Request $request): WP_REST_Response|WP_Error
    {
        $body = json_decode($request->get_body(), true);

        $file_path        = sanitize_text_field($body['filePath'] ?? '');
        $quarantined_path = sanitize_text_field($body['quarantinedPath'] ?? '');

        if (!$file_path || !$quarantined_path) {
            return new WP_Error('wsc_bad_request', 'filePath et quarantinedPath requis.', ['status' => 400]);
        }

        $result = $this->quarantine?->rollback($file_path, $quarantined_path);
        if ($result === null) {
            return new WP_Error('wsc_rollback_failed', 'Impossible de restaurer le fichier.', ['status' => 500]);
        }

        return new WP_REST_Response($result, 200);
    }
}
