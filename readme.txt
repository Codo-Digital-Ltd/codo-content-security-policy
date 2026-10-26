=== Codo Content Security Policy ===
Contributors: cododigital
Tags: content security policy, csp, security headers, xss, clickjacking
Requires at least: 6.2
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Just Content-Security-Policy, not a security suite. Starts in Report-Only, with draft policies, built-in violation reports and page scanning.

== Description ==

A Content Security Policy tells browsers which scripts, styles, fonts, images, frames and form targets your pages may use. Anything else is blocked, which stops a whole class of attacks: scripts injected from other hosts, data sent to attackers' servers, forms hijacked to post elsewhere, and your site being framed for clickjacking.

The hard part is building a policy without breaking the site. Codo Content Security Policy is designed around that.

It is built by [Codo Digital](https://codo.digital), a UK web development and managed hosting company, and is the policy plugin we use on our own clients' sites. Everything is free. There is no Pro version, no upsell, no account to create and no tracking.

= Safe by default =

* **Starts in Report-Only.** On activation the policy is sent as `Content-Security-Policy-Report-Only`: nothing is blocked, and browsers report what *would* be. When the reports are clean, enforce it with one button.
* **A sensible starting policy** for WordPress: same-site resources, core's emoji images and emoji-test worker, Gravatar, no plugins (`object-src 'none'`), no `<base>` hijacking, forms posting only to your site, and no framing by other sites.
* **The admin area is never covered.** Even a broken enforced policy cannot lock you out of the screen that fixes it. There is also a `wp-config.php` kill switch.

= Changing an enforced policy without breaking it =

* **Adding a source applies straight away.** Adding to an allowlist can only allow more, so it cannot break anything.
* **Tightening goes into a draft.** Removing a source, adding a hash, or anything else that could block something loading today is held in a draft. The draft is sent as a Report-Only policy *alongside* the enforced one, so real visitors' browsers test it without anything being blocked. When its reports are clean, promote it.
* **New directives inherit.** Creating `frame-src` for YouTube would normally stop it falling back to `default-src`, silently blocking your own iframes. The plugin copies the inherited sources across first.

= Violation reports, built for slow sites =

* Reports are answered before your theme loads, with an empty `204` response.
* Chromium browsers batch reports, so one page view is usually one request.
* Identical reports are counted, not stored again, even when the same thing is blocked on every page. At most 500 different violations are kept, for 30 days. If the table fills up, the Reports tab says so rather than looking clean.
* Processing is rate-limited, and collection runs for a set period (1, 7 or 30 days) and then switches itself off.
* Each report has an **Allow** button. Anyone can send a report, so nothing is ever allowed automatically.
* You can send reports to an external collector (Sentry, report-uri.com and so on) instead.

= Scanning =

* After you publish or update content, the page is fetched in the background as a logged-out visitor. Every script, stylesheet, font, image, iframe, media file and form target is checked against the policy, including the fonts and images inside your site's own stylesheets. Stylesheets hosted elsewhere are never downloaded; for Google Fonts and Bunny Fonts the font host is filled in automatically.
* Problems show in the posts list, in the editor, and on the Scan tab, each with an **Allow** button.
* You can scan any page, the login page, or your 20 most recently updated pages.
* Scans also warn when the server, a CDN or another plugin sends a second policy, and when the headers grow past 4 KB, which breaks NGINX's default FastCGI buffers.

= Also =

* **Login page policy:** wp-login.php gets its own rules, because reCAPTCHA, Turnstile and two-factor plugins load scripts there.
* **Presets** for common services: Google Analytics, Tag Manager, Fonts and Maps, reCAPTCHA, Turnstile, YouTube, Vimeo, Stripe, PayPal, Gravatar, Jetpack, Meta Pixel, Hotjar and Microsoft Clarity.
* **Page builders keep working:** no policy is sent in the Customizer preview or in Elementor, Divi, Beaver Builder, Bricks, Oxygen, WPBakery, Thrive, Brizy or Avada's front-end editors, for users who can edit.
* **Page caches are purged** when the policy changes, so visitors get the new headers. Supported: WP Super Cache, W3 Total Cache, WP Rocket, LiteSpeed Cache, Nginx Helper, SiteGround Optimizer, WP-Optimize and Breeze.
* **Multisite:** network defaults that every site adds to.
* **Post embeds keep working:** `frame-ancestors` is left out of `/embed/` pages, which exist to be framed by other sites.
* **No JavaScript on the settings screen**, so it cannot conflict with other plugins' admin scripts.

= Why 'unsafe-inline' is in the starting policy =

Almost every WordPress site prints inline scripts (core, themes and plugins all do). The strict alternatives don't fit most sites: nonces don't survive full-page caching, and hashes break whenever an inline script changes. So the starting policy keeps `'unsafe-inline'` for scripts and styles and works as an allowlist. It still blocks scripts from hosts you haven't listed, `eval`, plugins, `<base>` hijacking, form hijacking, data exfiltration through `connect-src`, and clickjacking.

If your site can do without inline scripts, remove `'unsafe-inline'` from `script-src`. The change goes through a draft first, and the Reports tab shows exactly what breaks.

= For hosts and agencies: configuration in wp-config.php =

`
define( 'CODO_CSP_DISABLE', true );                    // Send no policy headers at all.
define( 'CODO_CSP_MODE', 'enforce' );                  // Or 'report-only'.
define( 'CODO_CSP_REPORT_URI', 'https://example.report-uri.com/r/d/csp/enforce' );
define( 'CODO_CSP_LOGIN', false );                     // No policy on wp-login.php.
`

Constants override the settings screen and show as read-only there.

= For developers =

* `codo_csp_headers` filter: change the headers before they are sent. Receives `array( name => array( values ) )` and the context (`site` or `login`).
* `codo_csp_skip_request` filter: return true to send no policy on a front-end request.
* `codo_csp_presets` filter: add or change presets.
* `codo_csp_default_rules` filter: change the policy a site starts with.
* `codo_csp_capability` filter: change who can manage the policy (default `manage_options`).
* `codo_csp_report_rate_limit` filter: report requests processed per minute (default 120).
* `codo_csp_max_report_rows` filter: different violations kept (default 500).
* `codo_csp_policy_changed` action: fires when a policy changes. Hook in to purge a cache or CDN the plugin doesn't know about.
* `codo_csp_purge_caches` action: fires after the plugin purges page caches.
* `codo_csp_mode_changed` action: fires when switching between Report-Only and enforced.

Source, issues and tests: [github.com/Codo-Digital-Ltd/codo-content-security-policy](https://github.com/Codo-Digital-Ltd/codo-content-security-policy).

== Installation ==

1. Install from Plugins > Add New, or upload the `codo-content-security-policy` folder to `/wp-content/plugins/`.
2. Activate the plugin. The policy starts in Report-Only and collects reports for 7 days.
3. Go to Settings > Content Security Policy. Add presets for the services your site uses, and use the Scan tab to check your main pages.
4. Browse the site, then check the Reports tab. Allow what you recognise.
5. When reports stop appearing, click **Enforce the policy**.

== Frequently Asked Questions ==

= How is this different from security plugins that include CSP? =

It only does Content Security Policy. Security suites tend to offer CSP as one setting among many, often a text box for the header with little help building it. This plugin is built around getting the policy right: it starts in Report-Only, collects violation reports on your own site, scans your pages for the sources they use, and puts changes to an enforced policy through a draft first.

It adds no firewall, login protection or malware scanning, so it sits alongside whichever security plugin you already use. Just make sure that plugin isn't also sending a policy header; the scan warns you if one is.

= Will this break my site? =

Not while it's in Report-Only, which is how it starts: browsers only report. Enforce it once the Reports tab is quiet. After that, changes that could block something go through a draft first.

= Why aren't logged-in users excluded? =

They're the users an attack on the front end usually targets, because their browser holds an admin session. So the front end gets the same policy for everyone. The only exceptions are page builders and the Customizer preview (see below). Note that the admin bar adds a few requests for logged-in users that visitors don't make, so expect a few reports that only logged-in users trigger.

= My page builder or the Customizer stopped working =

Front-end editors inject inline code that an enforced policy blocks, so no policy is sent inside them by default. This applies to the Customizer preview and to Elementor, Divi, Beaver Builder, Bricks, Oxygen, WPBakery, Thrive, Brizy and Avada, for users who can edit. Make sure "Page builders" is ticked on the Settings tab. For other builders, use the `codo_csp_skip_request` filter.

= I changed the policy but visitors still get the old one =

Full-page caches store the headers with the page. The plugin purges the common cache plugins when the policy changes. For anything else, such as Cloudflare, Varnish, NGINX `fastcgi_cache` without Nginx Helper, or your host's cache, purge it yourself or hook `codo_csp_purge_caches`.

= Why does the scan say another policy header is being sent? =

Browsers enforce every policy they receive, so a second one (from your server configuration, a CDN, a security plugin or your host) can block something this plugin allows. Remove the other one, or make sure it allows at least as much. A page cache still holding an older version of this plugin's header can also cause the warning; purge it and scan again.

= My site returns 502 errors after adding many sources =

NGINX's default FastCGI buffer is 4 KB or 8 KB, and a large policy can exceed it ("upstream sent too big header"). The policy screen shows the header size and warns over 4 KB. Remove sources you no longer need (wildcards like `https://*.example.com` can replace several hosts), or raise `fastcgi_buffer_size` and `fastcgi_buffers`.

= Why can't I add 'https:' or * to script-src? =

It would allow scripts from any host, which defeats the policy. Add the specific hosts instead. The same applies to `https://*`, `data:` and `blob:`, and to `default-src` (which covers scripts when `script-src` is absent), `object-src`, `worker-src` and `base-uri`. Workers may use `blob:`, because WordPress's emoji loader needs it.

= Why can't I add a nonce? =

Nonces must change on every response, so they can't be a fixed source. They also don't survive full-page caching. Use a hash for a specific inline script, keeping in mind that browsers ignore `'unsafe-inline'` once a hash is present.

= A report says something was blocked on a page I don't recognise =

Anyone can send reports to your site, and browser extensions inject content that violates every policy (the plugin drops reports it can identify as extensions). Only allow sources you recognise. Sources a scan also found are marked.

= Do reports slow the site down? =

Very little. They are handled before the theme loads and `init` runs, and processing is rate-limited (120 requests a minute by default). Identical reports update a counter instead of adding rows. Collection also switches itself off at the end of the period you choose.

= How long are reports kept? =

Reports not seen for 30 days are deleted by a daily WP-Cron task, and you can clear them at any time. Reports store the directive, the blocked origin (not the full URL) and the latest page it happened on (the path, not the query string). No IP addresses or user agents are stored.

= Does the plugin send data to Codo Digital? =

No.

= Is it multisite compatible? =

Yes. Each site has its own policy, mode and reports, managed by its administrators. Network administrators can add network defaults (Network Admin > Settings > Content Security Policy). These are merged into every site's policy and can't be removed by site administrators. A network default that creates a directive on a site keeps the sources that site inherited for it, so adding one never blocks a site's own resources. `'none'`, hashes and `'strict-dynamic'` can't be network defaults. Removing a network default applies to every site straight away, without a draft.

== External services ==

The plugin does not contact any third-party service, collect usage data or track visitors or administrators.

* **Scanning stays on your site:** scans request pages and stylesheets from your own site only (a loopback request, like Site Health makes), and refuse redirects to other sites. Stylesheets hosted elsewhere are never downloaded.
* **Presets are host names, not downloads:** presets such as Stripe, Google Fonts or reCAPTCHA only add those services' host names to the policy your site sends, so your visitors' browsers are allowed to load what your theme and plugins already use. This plugin never loads anything from them.
* **External report collector (optional, off by default):** if you enter a collector URL (or define `CODO_CSP_REPORT_URI`), your visitors' browsers send violation reports straight to that URL instead of your own site. Each report holds the page URL, the blocked URL, the directive and, depending on the browser, a short sample of the blocked code. Nothing is sent anywhere else if the setting is left empty. The terms and privacy policy are those of whoever runs the URL you choose.

== Changelog ==

= 1.0.0 =
* First release: front-end and login policies, Report-Only by default, enforced mode with draft policies, built-in aggregated violation reports, page scanning after publishing, presets, page builder exclusions, cache purging, multisite network defaults and wp-config.php constants.

== Upgrade Notice ==

= 1.0.0 =
First release.
