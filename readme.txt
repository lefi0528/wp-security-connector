=== WP Security Connector ===
Contributors: genisoftweb
Tags: malware, security, scanner, security-audit, hacked
Requires at least: 6.0
Tested up to: 6.8
Requires PHP: 8.0
Stable tag: 0.8.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Connecteur sécurisé qui relie votre WordPress au scanner de malwares WP Security : audit, détection (webshells, backdoors), nettoyage à distance.

== Description ==

**WP Security Connector** est le plugin officiel du service **[WP Security](https://wordpress.genisoft.fr)** — une solution d'**audit de sécurité, de détection de malwares et de nettoyage automatisé** pour WordPress.

Ce plugin est un **connecteur léger** : il n'analyse rien lui-même. Il expose une **API REST authentifiée par HMAC-SHA256** que le moteur de scan de WP Security interroge pour auditer votre site **à distance**, sans SSH ni FTP. L'analyse lourde (détection de **webshells, backdoors, injections, code obfusqué**, vérification d'intégrité du cœur WordPress via les checksums officiels de `api.wordpress.org`, règles YARA) tourne **côté serveur**, dans un environnement isolé — votre site reste léger et rapide.

**Ce que le scanner détecte :**

* Webshells et backdoors PHP
* Injecteurs et redirections malveillantes
* Code obfusqué / encodé
* Fichiers du cœur WordPress modifiés
* Plugins et thèmes vulnérables (CVE)
* Code injecté en base de données (wp_options, etc.)

**Sécurité par conception :**

* Authentification HMAC-SHA256 sur chaque requête (signature + horodatage, anti-rejeu 5 min). Clé unique par site, générée à l'installation.
* **Lecture seule par défaut** : les fichiers sont lus pour analyse, jamais exécutés (aucun `eval`, `exec` ou `include` sur du contenu externe).
* Actions de nettoyage **réversibles** : quarantaine et remplacement par fichiers officiels re-téléchargés depuis wordpress.org, sous backup vérifié + nonce à usage unique.
* Pas de SSH, pas de SFTP.

= Service tiers requis =

Ce plugin est un connecteur : il **nécessite un compte sur le service externe WP Security** (`https://wordpress.genisoft.fr`) pour fonctionner. À chaque scan que vous déclenchez depuis votre tableau de bord WP Security, le service interroge l'API REST du plugin pour lire les fichiers à analyser. Les **contenus de fichiers ne sont pas stockés** par le service — seuls les résultats d'analyse (métadonnées) sont conservés ; hébergement en région UE (RGPD).

* Site du service : https://wordpress.genisoft.fr
* Conditions d'utilisation : https://wordpress.genisoft.fr/legal/cgu
* Politique de confidentialité : https://wordpress.genisoft.fr/legal/confidentialite

== Installation ==

1. Téléversez le dossier `wp-security-connector` dans `/wp-content/plugins/`, ou installez le plugin via le menu **Extensions → Ajouter**.
2. Activez le plugin depuis le menu **Extensions** de WordPress. Une clé HMAC unique est générée automatiquement.
3. Allez dans **Réglages → WP Security Connector** et copiez l'URL du site ainsi que la clé de connexion.
4. Créez un compte sur [wordpress.genisoft.fr](https://wordpress.genisoft.fr/sites/new), connectez votre site et lancez votre premier scan.

== Frequently Asked Questions ==

= Le plugin ralentit-il mon site ? =

Non. Le connecteur ne fait qu'exposer une API en lecture ; toute l'analyse lourde tourne sur les serveurs de WP Security, pas sur votre hébergement.

= Ai-je besoin d'un compte WP Security ? =

Oui. Le plugin est un connecteur vers le service WP Security ; il ne fonctionne pas seul. La connexion d'un site et un scan de découverte sont possibles gratuitement.

= Le plugin peut-il modifier mes fichiers ? =

Par défaut, non : il est en lecture seule. Les actions de nettoyage (quarantaine, remplacement) sont opt-in, réversibles, et protégées par HMAC + nonce à usage unique, toujours après un backup vérifié.

= Mes fichiers sont-ils envoyés à un tiers ? =

Seuls les fichiers nécessaires à l'analyse sont lus à la demande lors d'un scan. Ils ne sont pas stockés : seuls les résultats (métadonnées) sont conservés, en région UE.

== Changelog ==

= 0.8.0 =
* Scan de la base de données (endpoint lecture seule `/db`, pré-filtré en SQL, valeurs sensibles masquées).
* Protocole HMAC v2 : la query string est désormais signée.
* Endpoints de nettoyage réversible (quarantaine, remplacement officiel, rollback) avec nonce à usage unique.

== Upgrade Notice ==

= 0.8.0 =
Active le scan de la base de données et renforce l'authentification HMAC (query signée). Réinstallation recommandée.
