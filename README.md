# Codo Content Security Policy

[![CI](https://github.com/Codo-Digital-Ltd/codo-content-security-policy/actions/workflows/ci.yml/badge.svg)](https://github.com/Codo-Digital-Ltd/codo-content-security-policy/actions/workflows/ci.yml)
![Coverage](https://img.shields.io/badge/coverage-%E2%89%A595%25-brightgreen)
![PHP](https://img.shields.io/badge/PHP-7.4%E2%80%938.4-777bb4)
![WordPress](https://img.shields.io/badge/WordPress-6.2%2B-21759b)

Content-Security-Policy headers for WordPress. The policy starts in Report-Only, and changes that could break an enforced policy are tested in a draft first. Includes built-in violation reports and asset scanning. Free, with no Pro tier, upsells or telemetry.

Built and maintained by [Codo Digital](https://cododigital.co.uk). User-facing documentation is in [`readme.txt`](readme.txt) (the WordPress.org listing).

## How it works

```
front-end request ─ send_headers ─► HeaderSender ─┬─ PolicyStore: network defaults ∪ site rules (live)
wp-login.php ───── login_init ───┘                 ├─ draft (enforcing only) → second header, Report-Only
                                                   └─ Settings: mode, reporting window, constants

browser report ─► /?codo_csp_report=<token>  (plugins_loaded, before theme/init)
                   └─ ReportEndpoint → RateLimiter → ReportParser → ReportRepository (aggregated, capped)

publish/update ─► WP-Cron ─► Scanner (loopback fetch + stylesheets) ─► HtmlParser ─► Policy::allows()
```

- **Report-Only first:** activation seeds a WordPress-friendly allowlist policy, sends it as `Content-Security-Policy-Report-Only`, and collects reports for 7 days.
- **Live vs draft:** when enforcing, `PolicyStore` checks every change with `Policy::is_loosening_of()`. The check runs per directive, after fallback, and treats hashes and `'strict-dynamic'` as cancelling `'unsafe-inline'`. A change that only loosens the policy goes live. A change that tightens it goes into a draft, which is sent as a Report-Only header next to the enforced one.
- **No silent fallback breakage:** creating a fetch directive copies the sources it used to inherit (e.g. `frame-src` gets `default-src`'s `'self'`).
- **Network defaults only add:** `PolicyStore::compose()` merges them into each site's rules the same way, so a network `style-src-elem` for a CDN keeps each site's `'self'`.
- **Admin excluded:** `send_headers` never fires in wp-admin, admin-ajax, REST or cron. A broken policy can always be fixed from the admin screen.

## Naming and collisions

| Kind | Name |
| --- | --- |
| PHP namespace | `CodoDigital\Csp\` (PSR-4, own autoloader, no Composer at runtime) |
| Constants | `CODO_CSP_*` |
| Options / transients | `codo_csp_settings`, `codo_csp_policy`, `codo_csp_network_policy` (site option), `codo_csp_db_version`, `codo_csp_url_scans`, `codo_csp_report_rate`, `codo_csp_notice_{user}` |
| Post meta | `_codo_csp_scan`, `_codo_csp_scan_status` |
| Database table | `{prefix}codo_csp_reports` |
| Cron hooks | `codo_csp_purge_reports`, `codo_csp_scan_post`, `codo_csp_scan_batch`, `codo_csp_scan_url` |
| Hooks we add | `codo_csp_*` |
| Admin actions / pages | `codo_csp_*`, `codo-csp`, `codo-csp-network` |
| Query vars | `codo_csp_report`, `codo_csp_scan` |
| Text domain / slug | `codo-content-security-policy` |

No admin JavaScript is enqueued. The only script is a few inline lines in the block editor that use core's `core/notices` store.

## Development

```bash
composer install
composer lint                 # WordPress Coding Standards + PHPCompatibility (7.4+)
composer test                 # PHPUnit
composer coverage             # needs pcov or Xdebug
php bin/coverage-gate.php build/clover.xml 95
```

Tests are unit tests with [Brain Monkey](https://giacomogaliano.github.io/brain-monkey/) standing in for WordPress. They cover failure paths as well as the happy path:

- source validation and header injection
- CSP source matching, including scheme upgrades, wildcards, ports and paths
- fallback chains and the loosening check
- draft routing
- network defaults
- malformed and hostile reports, rate limits and the table cap
- loopback failures and foreign CSP headers
- missing nonces and capabilities

## Releasing

1. In a pull request, bump the version in `codo-content-security-policy.php` (header and `CODO_CSP_VERSION`) and `readme.txt` (`Stable tag` and a `= x.y.z =` changelog entry). CI fails if they disagree.
2. Merge to `main`.

The [Release workflow](.github/workflows/release.yml) then:

1. runs every check;
2. deploys the release to the WordPress.org SVN repository;
3. tags `vX.Y.Z` and publishes a GitHub release with the zip.

WordPress.org then offers the update to every site running the plugin.

- **Retries:** WordPress.org SVN itself decides whether a version is already released, so a release that fails half-way is retried on the next push.
- **Non-release pushes:** pushes that don't change the version only sync `readme.txt` and `.wordpress-org/` assets.
- **Before approval:** until WordPress.org approves the plugin, the deploy is skipped with a notice.

CI runs once per pull request (not again for the branch push). Use **Run workflow** to check a branch that has no pull request.

Secrets required, in a `wordpress-org` environment: `SVN_USERNAME`, `SVN_PASSWORD`. All third-party actions are pinned to commit SHAs. Banner and icon images for the directory go in `.wordpress-org/`.

## Security

See [SECURITY.md](SECURITY.md).

## Licence

GPL-2.0-or-later.
