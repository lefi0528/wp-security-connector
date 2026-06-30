=== Genisoft Security Connector ===
Contributors: genisoftweb
Tags: malware, security, scanner, security-audit, hacked
Requires at least: 6.0
Tested up to: 7.0
Requires PHP: 8.0
Stable tag: 0.8.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Secure read-only connector linking your WordPress site to the WP Security malware-scanning service for remote security audits.

== Description ==

**Genisoft Security Connector** is the official plugin for **[WP Security](https://wordpress.genisoft.fr)** (by Genisoft) — a remote **security audit and malware detection** service for WordPress.

This plugin is a **lightweight connector**: it performs no analysis itself. It exposes a **read-only REST API authenticated with HMAC-SHA256** that the WP Security engine calls to audit your site **remotely**, without SSH or FTP. The heavy analysis (detection of **webshells, backdoors, injections, obfuscated code**, WordPress core integrity checks against the official `api.wordpress.org` checksums, and YARA rules) runs **on our servers**, in an isolated environment — your site stays light and fast.

**What the scanner detects:**

* PHP webshells and backdoors
* Injectors and malicious redirects
* Obfuscated / encoded code
* Modified WordPress core files
* Vulnerable plugins and themes (CVE)
* Code injected into the database (wp_options, etc.)

**Secure by design:**

* HMAC-SHA256 authentication on every request (signature + timestamp; requests older than 5 minutes are rejected). One unique key per site.
* **Read-only:** files are read for analysis, never executed (no `eval`, `exec` or `include` on external content).
* No SSH, no SFTP.

= Third-party service =

This plugin is a connector: it **requires an account on the external WP Security service** (`https://wordpress.genisoft.fr`) to be useful. Each time you start a scan from your WP Security dashboard, the service calls the plugin's read-only REST API to read the files to analyze. File contents are **not stored** by the service — only analysis results (metadata) are kept; hosting is in the EU (GDPR).

* Service website: https://wordpress.genisoft.fr
* Terms of service: https://wordpress.genisoft.fr/legal/cgu
* Privacy policy: https://wordpress.genisoft.fr/legal/confidentialite

== Installation ==

1. Upload the `genisoft-security-connector` folder to `/wp-content/plugins/`, or install the plugin via **Plugins → Add New**.
2. Activate the plugin from the **Plugins** menu in WordPress.
3. Go to **Settings → Genisoft Security** and copy your site URL and connection key.
4. Create an account at [wordpress.genisoft.fr](https://wordpress.genisoft.fr/sites/new), connect your site and run your first scan.

== Frequently Asked Questions ==

= Does the plugin slow down my site? =

No. The connector only exposes a read-only API; all the heavy analysis runs on the WP Security servers, not on your hosting.

= Do I need a WP Security account? =

Yes. The plugin is a connector to the WP Security service; it does not work on its own. Connecting a site and running a discovery scan are free.

= Can the plugin modify my files? =

No. This connector is strictly **read-only**: it never executes, modifies, deletes or moves your files.

= Are my files sent to a third party? =

Only the files needed for analysis are read on demand during a scan. They are not stored — only the results (metadata) are kept, hosted in the EU.

== Screenshots ==

1. The connector settings in the WordPress admin (site URL + connection key).
2. The WP Security dashboard: scan report (infected files, entry point, risk score).

== Changelog ==

= 0.8.0 =
* Read-only connector: info, files, file content and database scan endpoints.
* HMAC-SHA256 authentication with signed query string.

== Upgrade Notice ==

= 0.8.0 =
Read-only connector with database scanning and HMAC-SHA256 authentication.
