<?php

/**
 * Plugin Name: Genisoft Security Connector
 * Plugin URI:  https://wordpress.genisoft.fr
 * Description: Connecteur sécurisé pour l'audit WordPress. Expose une API REST
 *              authentifiée par HMAC-SHA256 utilisée par le moteur de scan SaaS.
 * Version:     0.8.0
 * Author:      Genisoft
 * Author URI:  https://www.genisoft.fr
 * License:     GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: genisoft-security-connector
 * Requires at least: 6.0
 * Requires PHP: 8.0
 *
 * SÉCURITÉ : Phase 1 — endpoints lecture seule (files, info). Phase 2 — endpoints
 * write (backup, quarantine, replace, rollback) avec HMAC + nonce à usage unique.
 * Jamais d'exec/eval/include sur du code externe.
 */

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit; // Accès direct interdit
}

define('WSC_VERSION', '0.8.0');
define('WSC_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('WSC_MIN_WP_VERSION', '6.0');
define('WSC_MIN_PHP_VERSION', '8.0');

// Vérifications de compatibilité avant de charger quoi que ce soit
function wsc_check_requirements(): bool
{
    if (version_compare(PHP_VERSION, WSC_MIN_PHP_VERSION, '<')) {
        add_action('admin_notices', function () {
            echo '<div class="notice notice-error"><p>' . sprintf(
                /* translators: %s: version PHP minimale requise */
                esc_html__('Genisoft Security Connector requiert PHP %s+.', 'genisoft-security-connector'),
                esc_html(WSC_MIN_PHP_VERSION)
            ) . '</p></div>';
        });
        return false;
    }
    if (version_compare($GLOBALS['wp_version'], WSC_MIN_WP_VERSION, '<')) {
        add_action('admin_notices', function () {
            echo '<div class="notice notice-error"><p>' . sprintf(
                /* translators: %s: version WordPress minimale requise */
                esc_html__('Genisoft Security Connector requiert WordPress %s+.', 'genisoft-security-connector'),
                esc_html(WSC_MIN_WP_VERSION)
            ) . '</p></div>';
        });
        return false;
    }
    return true;
}

add_action('plugins_loaded', function () {
    if (!wsc_check_requirements()) {
        return;
    }

    require_once WSC_PLUGIN_DIR . 'includes/class-hmac-auth.php';
    require_once WSC_PLUGIN_DIR . 'includes/class-file-manager.php';
    require_once WSC_PLUGIN_DIR . 'includes/class-quarantine-manager.php';
    require_once WSC_PLUGIN_DIR . 'includes/class-backup-manager.php';
    require_once WSC_PLUGIN_DIR . 'includes/class-db-scanner.php';
    require_once WSC_PLUGIN_DIR . 'includes/class-api-server.php';
    require_once WSC_PLUGIN_DIR . 'includes/class-admin-settings.php';

    $auth       = new WSC_Hmac_Auth();
    $files      = new WSC_File_Manager();
    $quarantine = new WSC_Quarantine_Manager($auth, $files);
    $backup     = new WSC_Backup_Manager();
    $db         = new WSC_Db_Scanner();
    $server     = new WSC_Api_Server($auth, $files, $quarantine, $backup, $db);
    $server->register_routes();

    // Page de réglages — uniquement en admin
    if (is_admin()) {
        new WSC_Admin_Settings();
    }
});

register_activation_hook(__FILE__, function () {
    // La clé API est saisie manuellement par l'admin depuis le tableau de bord SaaS.
    // On n'auto-génère PAS de clé à l'activation — l'utilisateur doit coller la sienne.
});

register_deactivation_hook(__FILE__, function () {
    // Ne supprime PAS la clé HMAC à la désactivation — elle est nécessaire pour reconnecter
});
