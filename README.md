# WP Security Connector

**Connecteur sécurisé qui relie votre site WordPress au scanner de malwares [WP Security](https://wordpress.genisoft.fr).**

[![WordPress](https://img.shields.io/badge/WordPress-6.0%2B-21759b)](https://wordpress.org/)
[![PHP](https://img.shields.io/badge/PHP-8.0%2B-777bb4)](https://www.php.net/)
[![Version](https://img.shields.io/badge/version-0.8.0-00b3c4)](https://wordpress.genisoft.fr)

> 🔒 Plugin officiel de **[WP Security](https://wordpress.genisoft.fr)** — la solution SaaS d'**audit, de détection de malwares et de nettoyage automatisé** pour WordPress (alternative à Sucuri / Wordfence / MalCare).

---

## À quoi sert ce plugin ?

`WP Security Connector` est un **connecteur léger et sécurisé**. Il n'analyse rien lui-même : il expose une **API REST authentifiée par HMAC-SHA256** que le moteur de scan de **[wordpress.genisoft.fr](https://wordpress.genisoft.fr)** interroge pour auditer votre site **à distance**, sans SSH ni FTP.

Le scan complet (détection de **webshells, backdoors, injections, obfuscation**, vérification d'intégrité du core via checksums officiels `api.wordpress.org`, règles **YARA**) tourne **côté serveur SaaS**, dans un environnement isolé — votre site reste léger.

👉 **Créez un compte et connectez votre site : [wordpress.genisoft.fr](https://wordpress.genisoft.fr/sites/new)**

---

## Pourquoi c'est sûr

La sécurité est le cœur du produit, donc le connecteur est volontairement **minimaliste et durci** :

- ✅ **Authentification HMAC-SHA256** sur chaque requête (signature + horodatage, fenêtre anti-rejeu de 5 min). Clé unique par site, générée à l'installation, jamais transmise en clair.
- ✅ **Lecture seule par défaut** (Phase 1) : le connecteur lit vos fichiers octet par octet pour analyse — **jamais d'`eval`, `exec` ou `include`** sur du contenu externe.
- ✅ **Actions de nettoyage réversibles** (Phase 2) : quarantaine et remplacement par fichiers officiels re-téléchargés depuis `wordpress.org`, sous **backup vérifié + nonce à usage unique**. Aucune suppression destructive.
- ✅ **Pas de SSH, pas de SFTP, pas d'accès base hors périmètre.**

## Endpoints exposés

| Endpoint | Méthode | Phase | Rôle |
|---|---|---|---|
| `/wsc/v1/info` | GET | 1 | Version WP, plugins, thèmes (pour le diagnostic) |
| `/wsc/v1/files` | GET | 1 | Listing des fichiers à analyser |
| `/wsc/v1/file` | GET | 1 | Lecture d'un fichier (analyse statique) |
| `/wsc/v1/backup` · `/quarantine` · `/replace` · `/rollback` | POST | 2 | Nettoyage réversible (HMAC + nonce) |

Tous les endpoints sont sous le namespace `wsc/v1` et **rejettent toute requête non signée**.

## Installation

1. Téléchargez `wp-security-connector.zip`.
2. Dans votre admin WordPress : **Extensions → Ajouter → Téléverser une extension**.
3. Activez le plugin. Une clé HMAC unique est générée automatiquement.
4. Allez dans **Réglages → WP Security Connector**, copiez l'URL + la clé.
5. Connectez le site depuis votre **[tableau de bord WP Security](https://wordpress.genisoft.fr/sites/new)** et lancez votre premier scan.

**Prérequis :** WordPress 6.0+, PHP 8.0+.

---

## En savoir plus

- 🌐 **Site & tableau de bord :** [wordpress.genisoft.fr](https://wordpress.genisoft.fr)
- 🛡️ **Ce que détecte le scanner :** webshells, backdoors, injecteurs, code obfusqué, fichiers core modifiés, plugins/thèmes vulnérables (CVE).
- 🇪🇺 **Hébergement EU / RGPD :** vos fichiers ne sont **pas stockés** — seuls les résultats d'analyse (métadonnées) sont conservés.

> Ce dépôt contient **uniquement le connecteur** (open pour la transparence et l'audit communautaire). Le moteur de détection (scanner, règles YARA) reste propriétaire.

## Licence

Le **plugin** (ce dépôt) est distribué sous **GPLv2 ou ultérieure** — voir [`LICENSE`](LICENSE), comme requis pour le répertoire WordPress.org. Le **service WP Security** (backend de détection) reste un service propriétaire distinct.

---

*WP Security Connector — le pont sécurisé entre WordPress et [WP Security](https://wordpress.genisoft.fr).*
