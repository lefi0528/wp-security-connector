<?php

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit; // Acces direct interdit
}

/**
 * Vérification des signatures HMAC-SHA256 sur les requêtes entrantes.
 *
 * Protocole (v2 — signe AUSSI la query string, cf. B2 audit 2026-06) :
 *   X-WSC-Timestamp  : epoch Unix (string)
 *   X-WSC-Signature  : HMAC-SHA256(secret, METHOD\nROUTE\nCANONICAL_QUERY\nTIMESTAMP\nSHA256(BODY))
 *
 * CANONICAL_QUERY : paramètres de query triés par clé, au format `clé=valeur`
 *   (valeurs décodées) joints par `&`, en EXCLUANT les paramètres internes WP
 *   (rest_route en permaliens simples, _wpnonce, _locale…). Sans ça, un attaquant
 *   pouvait réécrire ?path= d'une requête signée vers wp-config.php sans invalider
 *   la signature (lecture arbitraire de fichiers).
 *
 * La requête est rejetée si :
 *   - Le timestamp est absent ou décale de > 5 minutes (replay attack)
 *   - La signature ne correspond pas
 */
class WSC_Hmac_Auth
{
    private const MAX_CLOCK_SKEW_SECONDS = 300; // 5 minutes

    public function verify(WP_REST_Request $request): bool
    {
        $timestamp = $request->get_header('X-WSC-Timestamp');
        $signature = $request->get_header('X-WSC-Signature');

        if (!$timestamp || !$signature) {
            return false;
        }

        // Vérification de la fenêtre temporelle (anti-replay)
        $now = time();
        if (abs($now - (int) $timestamp) > self::MAX_CLOCK_SKEW_SECONDS) {
            return false;
        }

        $secret = (string) get_option('wsc_hmac_secret', '');
        if (empty($secret)) {
            return false;
        }

        $body_hash = hash('sha256', $request->get_body());
        $signed_string = implode("\n", [
            $request->get_method(),
            $request->get_route(),
            $this->canonical_query($request),
            $timestamp,
            $body_hash,
        ]);

        $expected = hash_hmac('sha256', $signed_string, $secret);

        // Comparaison à temps constant — protection timing attack
        return hash_equals($expected, $signature);
    }

    /**
     * Comme verify(), mais à USAGE UNIQUE (M-HMAC-1) : la signature est mémorisée
     * pendant sa fenêtre de validité (5 min) et rejouée → refusée. À utiliser sur les
     * endpoints d'état sans nonce (ex. /backup) pour empêcher l'empilement par rejeu.
     */
    public function verify_no_replay(WP_REST_Request $request): bool
    {
        if (!$this->verify($request)) {
            return false;
        }
        $signature = (string) $request->get_header('X-WSC-Signature');
        $key = 'wsc_sig_' . hash('sha256', $signature);
        if (get_transient($key) !== false) {
            return false; // signature déjà utilisée (rejeu)
        }
        set_transient($key, 1, self::MAX_CLOCK_SKEW_SECONDS);
        return true;
    }

    /**
     * Sérialise canoniquement la query string pour la signature : clés triées,
     * `clé=valeur` (décodé) joints par `&`, sans les paramètres internes WordPress.
     */
    private function canonical_query(WP_REST_Request $request): string
    {
        $params = $request->get_query_params();
        $pairs = [];
        foreach ($params as $key => $value) {
            // rest_route (permaliens simples) + params préfixés `_` (_wpnonce, _locale)
            // ne font pas partie du contrat applicatif : les exclure des deux côtés.
            if ($key === 'rest_route' || str_starts_with((string) $key, '_')) {
                continue;
            }
            $pairs[(string) $key] = is_array($value) ? implode(',', $value) : (string) $value;
        }
        ksort($pairs);
        $parts = [];
        foreach ($pairs as $key => $value) {
            $parts[] = $key . '=' . $value;
        }
        return implode('&', $parts);
    }
}
