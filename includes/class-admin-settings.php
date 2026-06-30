<?php

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit; // Accès direct interdit
}

/**
 * Page d'administration Genisoft Security Connector.
 *
 * Permet à l'administrateur WordPress de saisir la clé API
 * générée par le tableau de bord SaaS.
 *
 * Accessible via : Réglages → Genisoft Security
 */
class WSC_Admin_Settings
{
    private const OPTION_KEY   = 'wsc_hmac_secret';
    private const MENU_SLUG    = 'wp-security-connector';
    private const SETTINGS_GROUP = 'wsc_settings_group';

    public function __construct()
    {
        add_action('admin_menu', [$this, 'add_settings_page']);
        add_action('admin_init', [$this, 'register_settings']);
    }

    public function add_settings_page(): void
    {
        add_options_page(
            __('Genisoft Security Connector', 'genisoft-security-connector'),
            __('Genisoft Security', 'genisoft-security-connector'),
            'manage_options',
            self::MENU_SLUG,
            [$this, 'render_page'],
        );
    }

    public function register_settings(): void
    {
        register_setting(self::SETTINGS_GROUP, self::OPTION_KEY, [
            'type'              => 'string',
            'sanitize_callback' => [$this, 'sanitize_api_key'],
            'default'           => '',
        ]);

        add_settings_section(
            'wsc_main_section',
            __('Configuration de la connexion', 'genisoft-security-connector'),
            fn() => null,
            self::MENU_SLUG,
        );

        add_settings_field(
            'wsc_hmac_secret_field',
            __('Clé API', 'genisoft-security-connector'),
            [$this, 'render_api_key_field'],
            self::MENU_SLUG,
            'wsc_main_section',
        );
    }

    public function sanitize_api_key(mixed $value): string
    {
        $sanitized = sanitize_text_field((string) $value);
        // La clé doit faire 64 caractères hexadécimaux (32 bytes)
        if (!empty($sanitized) && !preg_match('/^[0-9a-f]{64}$/', $sanitized)) {
            add_settings_error(
                self::OPTION_KEY,
                'wsc_invalid_key',
                __('La clé API doit faire 64 caractères hexadécimaux. Copiez-la depuis votre tableau de bord WP Security.', 'genisoft-security-connector'),
                'error'
            );
            return (string) get_option(self::OPTION_KEY, '');
        }
        return $sanitized;
    }

    public function render_api_key_field(): void
    {
        $value = (string) get_option(self::OPTION_KEY, '');
        $is_configured = !empty($value);
        ?>
        <input
            type="password"
            id="wsc_hmac_secret"
            name="<?php echo esc_attr(self::OPTION_KEY); ?>"
            value="<?php echo esc_attr($value); ?>"
            class="regular-text"
            autocomplete="off"
            placeholder="<?php echo esc_attr__('Collez ici la clé API depuis votre tableau de bord', 'genisoft-security-connector'); ?>"
        />
        <p class="description">
            <?php if ($is_configured) : ?>
                <span style="color: #00a32a"><?php echo esc_html__('✓ Clé API configurée.', 'genisoft-security-connector'); ?></span>
                <?php echo esc_html__('Vous pouvez la remplacer en saisissant une nouvelle valeur.', 'genisoft-security-connector'); ?>
            <?php else : ?>
                <?php echo esc_html__('Trouvez votre clé API dans le', 'genisoft-security-connector'); ?>
                <a href="https://wordpress.genisoft.fr/sites/new" target="_blank" rel="noopener noreferrer"><?php echo esc_html__('tableau de bord WP Security', 'genisoft-security-connector'); ?></a> →
                <strong><?php echo esc_html__('Sites → Ajouter un site', 'genisoft-security-connector'); ?></strong>.
            <?php endif; ?>
        </p>
        <?php
    }

    public function render_page(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Accès refusé.', 'genisoft-security-connector'));
        }

        $is_configured = !empty(get_option(self::OPTION_KEY, ''));
        ?>
        <div class="wrap">
            <h1>
                <span style="display:inline-flex;align-items:center;gap:8px">
                    <svg width="24" height="24" fill="none" viewBox="0 0 24 24" stroke="#2563eb" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"/>
                    </svg>
                    <?php echo esc_html__('Genisoft Security Connector', 'genisoft-security-connector'); ?>
                </span>
            </h1>

            <p><?php echo esc_html__('Version du plugin :', 'genisoft-security-connector'); ?> <strong><?php echo esc_html(WSC_VERSION); ?></strong></p>

            <?php if ($is_configured) : ?>
                <div class="notice notice-success is-dismissible">
                    <p>
                        <strong><?php echo esc_html__('Plugin connecté.', 'genisoft-security-connector'); ?></strong> <?php echo esc_html__('Votre site est surveillé par WP Security SaaS.', 'genisoft-security-connector'); ?>
                        <a href="https://wordpress.genisoft.fr" target="_blank" rel="noopener noreferrer"><?php echo esc_html__('Ouvrir le tableau de bord →', 'genisoft-security-connector'); ?></a>
                    </p>
                </div>
            <?php else : ?>
                <div class="notice notice-warning">
                    <p>
                        <strong><?php echo esc_html__('Plugin non configuré.', 'genisoft-security-connector'); ?></strong>
                        <?php echo esc_html__('Saisissez votre clé API ci-dessous pour activer la surveillance de ce site.', 'genisoft-security-connector'); ?>
                    </p>
                </div>
            <?php endif; ?>

            <form method="post" action="options.php">
                <?php
                settings_fields(self::SETTINGS_GROUP);
                do_settings_sections(self::MENU_SLUG);
                submit_button(__('Enregistrer la clé API', 'genisoft-security-connector'));
                ?>
            </form>

            <hr>
            <h2><?php echo esc_html__('Informations système', 'genisoft-security-connector'); ?></h2>
            <table class="widefat striped" style="max-width:500px">
                <tbody>
                    <?php
                    $infos = [
                        'WordPress'   => get_bloginfo('version'),
                        'PHP'         => PHP_VERSION,
                        __('URL du site', 'genisoft-security-connector') => get_site_url(),
                        __('Statut HMAC', 'genisoft-security-connector') => $is_configured
                            ? __('✓ Configuré', 'genisoft-security-connector')
                            : __('✗ Non configuré', 'genisoft-security-connector'),
                    ];
                    foreach ($infos as $label => $value) {
                        echo '<tr><th>' . esc_html($label) . '</th><td>' . esc_html($value) . '</td></tr>';
                    }
                    ?>
                </tbody>
            </table>
        </div>
        <?php
    }
}
