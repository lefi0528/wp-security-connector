<?php

/**
 * Plugin Name: Genisoft Security Connector
 * Plugin URI:  https://wordpress.genisoft.fr
 * Description: Secure connector that exposes an HMAC-SHA256 authenticated, read-only REST API used by the WP Security malware-scanning service to audit your site remotely.
 * Version:     0.8.0
 * Author:      Genisoft
 * Author URI:  https://www.genisoft.fr
 * License:     GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: genisoft-security-connector
 * Requires at least: 6.0
 * Requires PHP: 8.0
 *
 * Read-only connector: exposes REST endpoints (info, files, file, db) that the WP Security
 * service reads over an HMAC-signed channel. Never executes, evals or includes external code.
 */

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit; // Direct access not allowed
}

define('GENISECO_VERSION', '0.8.0');
define('GENISECO_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('GENISECO_MIN_WP_VERSION', '6.0');
define('GENISECO_MIN_PHP_VERSION', '8.0');

// Compatibility checks before loading anything.
function geniseco_check_requirements(): bool
{
    if (version_compare(PHP_VERSION, GENISECO_MIN_PHP_VERSION, '<')) {
        add_action('admin_notices', function () {
            echo '<div class="notice notice-error"><p>' . sprintf(
                /* translators: %s: minimum required PHP version */
                esc_html__('Genisoft Security Connector requires PHP %s+.', 'genisoft-security-connector'),
                esc_html(GENISECO_MIN_PHP_VERSION)
            ) . '</p></div>';
        });
        return false;
    }
    if (version_compare($GLOBALS['wp_version'], GENISECO_MIN_WP_VERSION, '<')) {
        add_action('admin_notices', function () {
            echo '<div class="notice notice-error"><p>' . sprintf(
                /* translators: %s: minimum required WordPress version */
                esc_html__('Genisoft Security Connector requires WordPress %s+.', 'genisoft-security-connector'),
                esc_html(GENISECO_MIN_WP_VERSION)
            ) . '</p></div>';
        });
        return false;
    }
    return true;
}

add_action('plugins_loaded', function () {
    if (!geniseco_check_requirements()) {
        return;
    }

    require_once GENISECO_PLUGIN_DIR . 'includes/class-hmac-auth.php';
    require_once GENISECO_PLUGIN_DIR . 'includes/class-file-manager.php';
    require_once GENISECO_PLUGIN_DIR . 'includes/class-db-scanner.php';
    require_once GENISECO_PLUGIN_DIR . 'includes/class-api-server.php';
    require_once GENISECO_PLUGIN_DIR . 'includes/class-admin-settings.php';

    $auth   = new GENISECO_Hmac_Auth();
    $files  = new GENISECO_File_Manager();
    $db     = new GENISECO_Db_Scanner();
    $server = new GENISECO_Api_Server($auth, $files, $db);
    $server->register_routes();

    // Settings page — admin only.
    if (is_admin()) {
        new GENISECO_Admin_Settings();
    }
});

register_activation_hook(__FILE__, function () {
    // The API key is entered manually by the admin from the SaaS dashboard.
    // No key is auto-generated on activation — the user pastes their own.
});

register_deactivation_hook(__FILE__, function () {
    // Keep the HMAC key on deactivation — it is needed to reconnect the site.
});
