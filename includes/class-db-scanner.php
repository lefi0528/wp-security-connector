<?php

declare(strict_types=1);

/**
 * Analyse LECTURE SEULE de la base de données WordPress pour détecter les infections
 * qui ne vivent pas dans des fichiers : code injecté dans wp_options, admins pirates,
 * cron malveillant, scripts/spam injectés dans les posts.
 *
 * SÉCURITÉ / RGPD :
 *  - PRÉ-FILTRAGE en SQL (LIKE) : seules les lignes contenant un token suspect quittent
 *    le site. Les options/posts propres ne sont JAMAIS exfiltrés.
 *  - Les options au NOM sensible (key/secret/password/token…) ont leur valeur MASQUÉE
 *    même si flaggées (un secret de plugin ne doit pas transiter).
 *  - Caviardage défensif des motifs de secret dans tout extrait renvoyé.
 *  - JAMAIS de user_pass / hash de mot de passe.
 *  - Aucune écriture, aucun eval/exec : on LIT des lignes et on cherche des sous-chaînes.
 */
class WSC_Db_Scanner
{
    /** Max de lignes signalées renvoyées par catégorie (anti-DoS / volume de données). */
    private const MAX_FLAGGED = 200;
    /** Longueur max d'un extrait renvoyé. */
    private const SNIPPET_LEN = 1200;

    /** Tokens injectables dans le pré-filtre SQL (sous-chaînes littérales sûres pour LIKE). */
    private const SQL_TRIGGERS = [
        'eval', 'base64_decode', 'gzinflate', 'gzuncompress', 'str_rot13', 'gzdecode',
        'system(', 'shell_exec', 'passthru', 'assert(', 'create_function', 'proc_open',
        'call_user_func', '<script', '<iframe', 'document.write', 'fromCharCode',
        'unescape(', 'atob(', 'wp_remote_get', 'file_get_contents',
    ];

    /** Tokens recherchés côté PHP sur les lignes déjà retournées (rapport plus fin). */
    private const ALL_TRIGGERS = [
        'eval', 'base64_decode', 'gzinflate', 'gzuncompress', 'gzdecode', 'str_rot13',
        'system(', 'shell_exec', 'passthru', 'assert(', 'create_function', 'proc_open',
        'popen(', 'call_user_func', 'preg_replace', 'chr(', '\\x',
        '<script', '<iframe', 'document.write', 'fromCharCode', 'unescape(', 'atob(',
        'wp_remote_get', 'file_get_contents', 'curl_exec',
    ];

    /** Fragments de nom d'option indiquant un SECRET → valeur masquée. */
    private const SECRET_NAME_FRAGMENTS = [
        'key', 'secret', 'password', 'passwd', 'pwd', 'token', 'salt', 'auth',
        'api', 'smtp', 'license', 'licence', 'private', 'oauth', 'client_secret',
    ];

    public function scan(): array
    {
        return [
            'options'    => $this->scan_options(),
            'users_priv' => $this->scan_privileged_users(),
            'cron'       => $this->scan_cron(),
            'posts'      => $this->scan_posts(),
            'generated'  => gmdate('c'),
        ];
    }

    // ─── Options ──────────────────────────────────────────────────────────────

    private function scan_options(): array
    {
        global $wpdb;
        [$where, $params] = $this->like_clause('option_value');
        // phpcs:ignore WordPress.DB.PreparedSQL -- $where = placeholders only, valeurs liées via prepare()
        $sql  = "SELECT option_name, option_value FROM {$wpdb->options} WHERE {$where} LIMIT " . (self::MAX_FLAGGED + 50);
        $rows = $wpdb->get_results($wpdb->prepare($sql, $params), ARRAY_A) ?: [];

        $flagged = [];
        foreach ($rows as $row) {
            $name     = (string) $row['option_name'];
            $value    = (string) $row['option_value'];
            $triggers = $this->find_triggers($value);
            if (empty($triggers)) {
                continue;
            }
            $is_secret = $this->is_secret_name($name);
            $flagged[] = [
                'name'     => $name,
                'triggers' => $triggers,
                'snippet'  => $is_secret
                    ? '[valeur masquée — option au nom sensible]'
                    : $this->snippet_around($value, $triggers),
                'redacted' => $is_secret,
                'size'     => strlen($value),
            ];
            if (count($flagged) >= self::MAX_FLAGGED) {
                break;
            }
        }
        return $flagged;
    }

    // ─── Utilisateurs privilégiés ───────────────────────────────────────────────

    private function scan_privileged_users(): array
    {
        // JAMAIS de user_pass. On renvoie les comptes admin/éditeur (peu nombreux) pour
        // détecter un admin pirate injecté (souvent récent, login/email atypique).
        $users = get_users([
            'role__in' => ['administrator', 'editor'],
            'number'   => 100,
            'fields'   => ['ID', 'user_login', 'user_email', 'user_registered'],
        ]);

        $out = [];
        $recent_cutoff = time() - 30 * 86400;
        foreach ($users as $u) {
            $roles  = get_userdata((int) $u->ID)->roles ?? [];
            $reg_ts = strtotime((string) $u->user_registered) ?: 0;
            $flags  = [];
            if ($reg_ts > $recent_cutoff) {
                $flags[] = 'recent';
            }
            if (preg_match('/[A-Za-z0-9]{12,}/', (string) $u->user_login) && !preg_match('/[aeiou]/i', (string) $u->user_login)) {
                $flags[] = 'login_atypique';
            }
            $out[] = [
                'login'      => (string) $u->user_login,
                'email'      => (string) $u->user_email,
                'roles'      => array_values((array) $roles),
                'registered' => (string) $u->user_registered,
                'flags'      => $flags,
            ];
        }
        return $out;
    }

    // ─── Cron ───────────────────────────────────────────────────────────────────

    private function scan_cron(): array
    {
        $cron = function_exists('_get_cron_array') ? (_get_cron_array() ?: []) : [];
        $flagged = [];
        foreach ($cron as $timestamp => $hooks) {
            if (!is_array($hooks)) {
                continue;
            }
            foreach (array_keys($hooks) as $hook) {
                $hook = (string) $hook;
                $reasons = $this->find_triggers($hook);
                // Hook au nom encodé/aléatoire (base64-like long sans tiret) = suspect.
                if (preg_match('/^[A-Za-z0-9+\/]{24,}={0,2}$/', $hook)) {
                    $reasons[] = 'nom_encodé';
                }
                if (empty($reasons)) {
                    continue;
                }
                $flagged[] = [
                    'hook'     => $hook,
                    'next_run' => gmdate('c', (int) $timestamp),
                    'reasons'  => array_values(array_unique($reasons)),
                ];
                if (count($flagged) >= self::MAX_FLAGGED) {
                    break 2;
                }
            }
        }
        return $flagged;
    }

    // ─── Posts publiés ──────────────────────────────────────────────────────────

    private function scan_posts(): array
    {
        global $wpdb;
        [$where, $params] = $this->like_clause('post_content');
        // phpcs:ignore WordPress.DB.PreparedSQL
        $sql  = "SELECT ID, post_type, post_status, post_title, post_content FROM {$wpdb->posts}
                 WHERE post_status = 'publish' AND ({$where}) LIMIT " . (self::MAX_FLAGGED + 50);
        $rows = $wpdb->get_results($wpdb->prepare($sql, $params), ARRAY_A) ?: [];

        $flagged = [];
        foreach ($rows as $row) {
            $content  = (string) $row['post_content'];
            $triggers = $this->find_triggers($content);
            if (empty($triggers)) {
                continue;
            }
            $flagged[] = [
                'id'       => (int) $row['ID'],
                'type'     => (string) $row['post_type'],
                'status'   => (string) $row['post_status'],
                'title'    => mb_substr((string) $row['post_title'], 0, 120),
                'triggers' => $triggers,
                'snippet'  => $this->snippet_around($content, $triggers),
            ];
            if (count($flagged) >= self::MAX_FLAGGED) {
                break;
            }
        }
        return $flagged;
    }

    // ─── Helpers ────────────────────────────────────────────────────────────────

    /** Construit `(col LIKE %s OR col LIKE %s …)` + les valeurs liées (esc_like). */
    private function like_clause(string $column): array
    {
        global $wpdb;
        $parts  = [];
        $params = [];
        foreach (self::SQL_TRIGGERS as $token) {
            $parts[]  = "{$column} LIKE %s";
            $params[] = '%' . $wpdb->esc_like($token) . '%';
        }
        return ['(' . implode(' OR ', $parts) . ')', $params];
    }

    private function find_triggers(string $value): array
    {
        $found = [];
        foreach (self::ALL_TRIGGERS as $token) {
            if (stripos($value, $token) !== false) {
                $found[] = $token;
            }
        }
        return array_values(array_unique($found));
    }

    private function is_secret_name(string $name): bool
    {
        $lower = strtolower($name);
        foreach (self::SECRET_NAME_FRAGMENTS as $frag) {
            if (str_contains($lower, $frag)) {
                return true;
            }
        }
        return false;
    }

    /** Extrait autour du 1er token + caviardage défensif des secrets résiduels. */
    private function snippet_around(string $value, array $triggers): string
    {
        $pos = false;
        foreach ($triggers as $token) {
            $p = stripos($value, $token);
            if ($p !== false && ($pos === false || $p < $pos)) {
                $pos = $p;
            }
        }
        $start = max(0, ($pos === false ? 0 : $pos) - 120);
        $snippet = substr($value, $start, self::SNIPPET_LEN);
        return $this->redact_secrets($snippet);
    }

    private function redact_secrets(string $s): string
    {
        $out = preg_replace(
            '/((?:password|passwd|pwd|secret|api[_-]?key|token|auth)\s*["\']?\s*[:=>]+\s*["\']?)[^\s"\',;]{4,}/i',
            '$1[caviardé]',
            $s,
        );
        return $out ?? $s;
    }
}
