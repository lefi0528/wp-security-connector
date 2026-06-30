<?php

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit; // Direct access not allowed
}

/**
 * WordPress REST endpoints (read-only).
 * Namespace: /wp-json/wsc/v1/
 *
 *   GET /info   — WP version, active plugins, theme
 *   GET /files  — recursive file list with SHA-256 hashes
 *   GET /file   — single file content (param: path)
 *   GET /db     — read-only DB scan (suspicious options/users/cron/posts, pre-filtered)
 *
 * Every endpoint requires a valid HMAC-SHA256 signature. Files are read byte by byte,
 * never executed or interpreted.
 */
class GENISECO_Api_Server
{
    private const NAMESPACE = 'wsc/v1';

    public function __construct(
        private readonly GENISECO_Hmac_Auth $auth,
        private readonly GENISECO_File_Manager $files,
        private readonly ?GENISECO_Db_Scanner $db = null,
    ) {}

    public function register_routes(): void
    {
        add_action('rest_api_init', function () {
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

            // Read-only DB scan. Pre-filtered and redacted on the plugin side.
            if ($this->db !== null) {
                register_rest_route(self::NAMESPACE, '/db', [
                    'methods'             => WP_REST_Server::READABLE,
                    'callback'            => [$this, 'handle_db_scan'],
                    'permission_callback' => [$this, 'check_hmac'],
                ]);
            }
        });
    }

    public function check_hmac(WP_REST_Request $request): bool|WP_Error
    {
        if (!$this->auth->verify($request)) {
            return new WP_Error('geniseco_unauthorized', 'Invalid or missing HMAC signature.', ['status' => 401]);
        }
        return true;
    }

    public function handle_info(WP_REST_Request $request): WP_REST_Response
    {
        $raw_plugins = get_option('active_plugins', []);
        $theme       = wp_get_theme();

        $plugins_with_versions = [];
        foreach ((array) $raw_plugins as $plugin_file) {
            $slug = explode('/', (string) $plugin_file)[0];
            $data = function_exists('get_plugin_data')
                ? get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin_file, false, false)
                : [];
            $plugins_with_versions[] = [
                'slug'    => $slug,
                'file'    => $plugin_file,
                'version' => $data['Version'] ?? null,
                'name'    => $data['Name'] ?? $slug,
            ];
        }

        return new WP_REST_Response([
            'wp_version'              => get_bloginfo('version'),
            'php_version'             => PHP_VERSION,
            'active_plugins'          => array_values((array) $raw_plugins),
            'active_plugins_extended' => $plugins_with_versions,
            'active_theme'            => [
                'name'    => $theme->get('Name'),
                'version' => $theme->get('Version'),
                'slug'    => get_stylesheet(),
            ],
            'site_url'                => get_site_url(),
            'abspath'                 => '', // Intentionally empty — relative paths only.
            'plugin_version'          => GENISECO_VERSION,
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
            return new WP_Error('geniseco_not_found', 'File not found or not readable.', ['status' => 404]);
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
            return new WP_Error('geniseco_not_found', 'DB scan not available.', ['status' => 404]);
        }
        return new WP_REST_Response($this->db->scan(), 200);
    }
}
