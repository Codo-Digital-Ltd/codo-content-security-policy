# Security policy

## Reporting a vulnerability

Please report security issues privately to **security@cododigital.co.uk**, or through GitHub's "Report a vulnerability" button on this repository. Do not open a public issue.

We aim to acknowledge reports within two UK business days and to ship a fix for confirmed high or critical issues within seven days. We credit reporters in the changelog unless asked not to.

## Supported versions

Only the latest release receives security fixes. WordPress.org offers updates to every site automatically.

## Design notes for researchers

- **Admin screens:** Settings > Content Security Policy (`manage_options`, filterable with `codo_csp_capability`). Network defaults are under Network Admin (`manage_network_options`).
- **Form handlers:** every admin form handler checks the capability and a nonce. There are no REST or AJAX endpoints.
- **Report endpoint:** the only unauthenticated endpoint is `/?codo_csp_report=<token>`, which accepts POSTs from browsers.
  - It does nothing unless built-in collection is switched on. The token in the URL (`hash_equals`) only filters out stray traffic: it appears in every page's headers, so it is not a secret.
  - It is rate-limited per minute, ignores bodies over 64 KB, and reads at most 50 reports per request.
  - Reports are reduced to the directive name, the blocked origin or a keyword, the page path (no query string) and the disposition. Reports about other hosts and from browser extensions are dropped.
  - Reports are aggregated by context, directive, blocked origin and disposition, keeping only the latest page. The table holds at most 500 rows. When it is full, new violations are counted as dropped and the Reports tab shows a warning, so forged reports can't make a quiet tab look clean. All values are escaped when shown.
  - Reported sources are never added to the policy automatically.
- **Source validation:** sources are validated against the CSP grammar before storage. Whitespace, `;`, `,`, quotes and control characters are rejected, so a source cannot inject a directive or a header.
  - In `default-src`, the script directives, `object-src`, `worker-src` and `base-uri`, sources that would allow code from anywhere are refused: `*`, any `*` host (`https://*`, `*:*`), `http:`, `https:`, `data:` and `blob:`. The one exception is `blob:` in `worker-src`.
  - Network defaults can't be `'none'`, hashes or `'strict-dynamic'`, which would restrict every site at once. A network default that creates a directive keeps each site's inherited sources.
- **Scanner:** it only fetches URLs on the site's own host and port (a loopback request). Redirects are followed by hand, at most three, and only while they stay on the site, so an open redirect can't point the scanner elsewhere. Linked stylesheets are fetched with `wp_safe_remote_get`, except same-host ones, which may resolve to a private address on local installs and go through the same loopback rules. A scan stops fetching after 20 seconds.
