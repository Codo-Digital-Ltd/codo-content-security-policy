<?php
/**
 * Fetches a page of this site and checks its assets against the policy.
 *
 * @package CodoDigital\Csp
 */

namespace CodoDigital\Csp\Scan;

use CodoDigital\Csp\Http\HeaderSender;
use CodoDigital\Csp\Policy\Directives;
use CodoDigital\Csp\Policy\Policy;
use CodoDigital\Csp\Policy\Source;
use CodoDigital\Csp\Settings\PolicyStore;

defined( 'ABSPATH' ) || exit;

/**
 * Scans a URL on this site the way an anonymous visitor sees it (a loopback
 * request), including the site's own stylesheets. Nothing is ever fetched
 * from another host: fonts used by well-known font services' stylesheets
 * (such as Google Fonts' fonts.gstatic.com) are inferred instead.
 */
class Scanner {

	const MAX_STYLESHEETS = 10;
	const MAX_HTML_BYTES  = 3145728;
	const MAX_CSS_BYTES   = 524288;
	const TIME_BUDGET     = 20;

	/**
	 * Font hosts used by off-site stylesheet hosts, which are never fetched.
	 *
	 * @var array<string, string>
	 */
	const KNOWN_FONT_HOSTS = array(
		'fonts.googleapis.com' => 'https://fonts.gstatic.com/',
		'fonts.bunny.net'      => 'https://fonts.bunny.net/',
	);

	/**
	 * When the current scan must stop fetching (microtime).
	 *
	 * @var float
	 */
	private $deadline = 0.0;

	/**
	 * Policies.
	 *
	 * @var PolicyStore
	 */
	private $store;

	/**
	 * Headers the site sends (to spot a second policy from elsewhere).
	 *
	 * @var HeaderSender
	 */
	private $headers;

	/**
	 * Parser.
	 *
	 * @var HtmlParser
	 */
	private $parser;

	/**
	 * Constructor.
	 *
	 * @param PolicyStore  $store   Policies.
	 * @param HeaderSender $headers Header builder.
	 * @param HtmlParser   $parser  Parser.
	 */
	public function __construct( PolicyStore $store, HeaderSender $headers, HtmlParser $parser ) {
		$this->store   = $store;
		$this->headers = $headers;
		$this->parser  = $parser;
	}

	/**
	 * Whether a URL is on this site (scans never fetch other hosts).
	 *
	 * @param string $url URL.
	 * @return bool
	 */
	public function is_own_url( $url ) {
		$target = Source::parse( $url );
		$home   = Source::parse( home_url( '/' ) );
		if ( null === $target || null === $home || ! in_array( $target['scheme'], array( 'http', 'https' ), true ) || $target['host'] !== $home['host'] ) {
			return false;
		}
		// The site's own port, or a default port (http and https versions of the site).
		return $target['port'] === $home['port'] || Source::DEFAULT_PORTS[ $target['scheme'] ] === $target['port'];
	}

	/**
	 * Fetch a URL on this site, following at most three redirects and only
	 * while they stay on this site (so an open redirect cannot point the
	 * scanner at internal services).
	 *
	 * @param string               $url  URL on this site.
	 * @param array<string, mixed> $args Request arguments.
	 * @return array<string, mixed>|\WP_Error
	 */
	private function loopback( $url, array $args ) {
		$args['redirection'] = 0;
		// Core's filter for loopback requests (Site Health uses it too).
		$args['sslverify'] = apply_filters( 'https_local_ssl_verify', false ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core hook.

		for ( $hop = 0; $hop <= 3; $hop++ ) {
			$args['timeout'] = $this->time_left( (int) $args['timeout'] );
			$response        = wp_remote_get( $url, $args );
			$code            = is_wp_error( $response ) ? 0 : (int) wp_remote_retrieve_response_code( $response );
			if ( $code < 300 || $code > 399 ) {
				return $response;
			}
			$location = (string) wp_remote_retrieve_header( $response, 'location' );
			$next     = '' === $location ? '' : UrlResolver::resolve( $location, $url );
			if ( '' === $next ) {
				return new \WP_Error( 'codo_csp_redirect', __( 'it redirects without saying where to', 'codo-content-security-policy' ) );
			}
			if ( ! $this->is_own_url( $next ) ) {
				return new \WP_Error(
					'codo_csp_redirect',
					/* translators: %s: URL. */
					sprintf( __( 'it redirects off this site, to %s', 'codo-content-security-policy' ), (string) Source::origin_of( $next ) )
				);
			}
			$url = $next;
		}
		return new \WP_Error( 'codo_csp_redirect', __( 'too many redirects', 'codo-content-security-policy' ) );
	}

	/**
	 * Seconds a request may take, within the scan's overall time budget.
	 *
	 * @param int $wanted Seconds the request would normally get.
	 * @return int At least 1.
	 */
	private function time_left( $wanted ) {
		return max( 1, min( $wanted, (int) floor( $this->deadline - microtime( true ) ) ) );
	}

	/**
	 * The context a URL belongs to.
	 *
	 * @param string $url URL.
	 * @return string site or login.
	 */
	public static function context_for( $url ) {
		$path = (string) wp_parse_url( $url, PHP_URL_PATH );
		return '/wp-login.php' === substr( $path, -13 ) ? 'login' : 'site';
	}

	/**
	 * Scan a URL.
	 *
	 * @param string      $url     URL on this site.
	 * @param string|null $context site or login; guessed from the URL when null.
	 * @return array<string, mixed> Result (see result()).
	 */
	public function scan( $url, $context = null ) {
		$context        = in_array( $context, array( 'site', 'login' ), true ) ? $context : self::context_for( $url );
		$this->deadline = microtime( true ) + self::TIME_BUDGET;
		if ( ! $this->is_own_url( $url ) ) {
			return $this->result( $url, $context, 'error', __( 'Only pages on this site can be scanned.', 'codo-content-security-policy' ) );
		}

		$response = $this->loopback(
			add_query_arg( array( 'codo_csp_scan' => time() ), $url ),
			array(
				'timeout'             => 15,
				'limit_response_size' => self::MAX_HTML_BYTES,
				'headers'             => array(
					'Cache-Control' => 'no-cache',
					'Accept'        => 'text/html',
				),
				'user-agent'          => self::user_agent(),
			)
		);

		if ( is_wp_error( $response ) ) {
			$message = 'codo_csp_redirect' === $response->get_error_code()
				/* translators: %s: reason, such as "it redirects off this site, to https://example.org". */
				? __( 'The page was not scanned: %s. Only pages on this site are fetched.', 'codo-content-security-policy' )
				/* translators: %s: error message. */
				: __( 'The page could not be fetched (%s). Some hosts block requests from a site to itself.', 'codo-content-security-policy' );
			return $this->result( $url, $context, 'error', sprintf( $message, $response->get_error_message() ) );
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			return $this->result(
				$url,
				$context,
				'error',
				sprintf(
					/* translators: %d: HTTP status code. */
					__( 'The page returned HTTP %d.', 'codo-content-security-policy' ),
					$code
				)
			);
		}

		$type = (string) wp_remote_retrieve_header( $response, 'content-type' );
		if ( '' !== $type && false === stripos( $type, 'html' ) ) {
			return $this->result( $url, $context, 'error', __( 'The page is not HTML.', 'codo-content-security-policy' ) );
		}

		if ( ! class_exists( '\DOMDocument' ) ) {
			return $this->result( $url, $context, 'error', __( 'Scanning needs the PHP DOM extension, which this server does not have.', 'codo-content-security-policy' ) );
		}

		$parsed    = $this->parser->parse_html( wp_remote_retrieve_body( $response ), $url );
		$resources = $parsed['resources'];
		foreach ( array_slice( array_unique( $parsed['stylesheets'] ), 0, self::MAX_STYLESHEETS ) as $stylesheet ) {
			if ( microtime( true ) >= $this->deadline ) {
				break; // Out of time: check what was found so far.
			}
			$resources = array_merge( $resources, $this->stylesheet_resources( $stylesheet ) );
		}

		$page_origin = (string) Source::origin_of( $url );
		$live        = $this->store->live( $context );
		$draft       = $this->store->draft( $context );
		$result      = $this->result( $url, $context, 'ok' );

		$result['issues']   = $this->evaluate( $live, $resources, $parsed['inline'], $page_origin );
		$result['draft']    = null === $draft ? array() : self::only_new( $this->evaluate( $draft, $resources, $parsed['inline'], $page_origin ), $result['issues'] );
		$result['checked']  = count( $resources );
		$result['warnings'] = $this->header_warnings( $response, $context );
		if ( ! empty( $result['issues'] ) || ! empty( $result['draft'] ) ) {
			$result['status'] = 'issues';
		}
		return $result;
	}

	/**
	 * The scanner's user agent (it identifies the plugin, not the site).
	 *
	 * @return string
	 */
	private static function user_agent() {
		return 'Codo-CSP-Scanner/' . ( defined( 'CODO_CSP_VERSION' ) ? CODO_CSP_VERSION : '1' );
	}

	/**
	 * List what a stylesheet loads. Only this site's stylesheets are fetched;
	 * for other hosts nothing is requested, and only the font host of a
	 * well-known font service is inferred.
	 *
	 * @param string $url Stylesheet URL.
	 * @return array<int, array{directive: string, url: string}>
	 */
	private function stylesheet_resources( $url ) {
		$parts = Source::parse( $url );
		if ( null === $parts || ! in_array( $parts['scheme'], array( 'http', 'https' ), true ) ) {
			return array();
		}
		if ( ! $this->is_own_url( $url ) ) {
			$host = strtolower( (string) $parts['host'] );
			return isset( self::KNOWN_FONT_HOSTS[ $host ] )
				? array(
					array(
						'directive' => 'font-src',
						'url'       => self::KNOWN_FONT_HOSTS[ $host ],
					),
				)
				: array();
		}
		// Same-site loopback: redirects off this site are refused, not followed.
		$response = $this->loopback(
			$url,
			array(
				'timeout'             => 5,
				'limit_response_size' => self::MAX_CSS_BYTES,
				'user-agent'          => self::user_agent(),
			)
		);
		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return array();
		}
		return $this->parser->parse_css( wp_remote_retrieve_body( $response ), $url );
	}

	/**
	 * Check resources and inline code against a policy.
	 *
	 * @param Policy                                            $policy    Policy.
	 * @param array<int, array{directive: string, url: string}> $resources Resources.
	 * @param array<string, int>                                $inline    Inline counts by directive.
	 * @param string                                            $page_origin      Page origin.
	 * @return array<int, array{directive: string, target: string, source: string, example: string, count: int, inline: bool}>
	 */
	public function evaluate( Policy $policy, array $resources, array $inline, $page_origin ) {
		$issues = array();
		foreach ( $resources as $resource ) {
			if ( $policy->allows( $resource['directive'], $resource['url'], $page_origin ) ) {
				continue;
			}
			$source = Source::origin_of( $resource['url'] );
			if ( null === $source ) {
				continue;
			}
			if ( $source === $page_origin ) {
				$source = "'self'";
			}
			$target = Directives::target( $policy, $resource['directive'] );
			$key    = $target . ' ' . $source;
			if ( isset( $issues[ $key ] ) ) {
				++$issues[ $key ]['count'];
				continue;
			}
			$issues[ $key ] = array(
				'directive' => $resource['directive'],
				'target'    => $target,
				'source'    => $source,
				'example'   => self::strip_query( $resource['url'] ),
				'count'     => 1,
				'inline'    => false,
			);
		}

		foreach ( $inline as $directive => $count ) {
			if ( $count > 0 && ! $policy->allows_inline( $directive ) ) {
				$issues[ 'inline ' . $directive ] = array(
					'directive' => $directive,
					'target'    => Directives::target( $policy, $directive ),
					'source'    => "'unsafe-inline'",
					'example'   => '',
					'count'     => (int) $count,
					'inline'    => true,
				);
			}
		}
		return array_values( $issues );
	}

	/**
	 * Draft issues the live policy does not already have (those are listed
	 * once, under the live policy).
	 *
	 * @param array<int, array<string, mixed>> $draft Draft issues.
	 * @param array<int, array<string, mixed>> $live  Live issues.
	 * @return array<int, array<string, mixed>>
	 */
	private static function only_new( array $draft, array $live ) {
		$seen = array();
		foreach ( $live as $issue ) {
			$seen[ $issue['directive'] . ' ' . $issue['source'] ] = true;
		}
		return array_values(
			array_filter(
				$draft,
				static function ( $issue ) use ( $seen ) {
					return ! isset( $seen[ $issue['directive'] . ' ' . $issue['source'] ] );
				}
			)
		);
	}

	/**
	 * Warn about policy headers this plugin did not send (from the server,
	 * a CDN or another plugin): browsers enforce every policy they receive,
	 * so a second one can block what this one allows.
	 *
	 * @param array<string, mixed> $response HTTP response.
	 * @param string               $context  Context.
	 * @return string[]
	 */
	private function header_warnings( $response, $context ) {
		$ours     = $this->headers->build( $context );
		$warnings = array();
		foreach ( array( 'Content-Security-Policy', 'Content-Security-Policy-Report-Only' ) as $name ) {
			$sent = wp_remote_retrieve_header( $response, strtolower( $name ) );
			$sent = is_array( $sent ) ? $sent : ( '' === $sent ? array() : array( $sent ) );
			$mine = isset( $ours[ $name ] ) ? array_map( array( __CLASS__, 'without_reporting' ), $ours[ $name ] ) : array();
			foreach ( $sent as $value ) {
				// WordPress core sends its own frame-ancestors policy on wp-login.php.
				$core_login = 'login' === $context && "frame-ancestors 'self'" === self::without_reporting( (string) $value );
				if ( ! $core_login && ! in_array( self::without_reporting( (string) $value ), $mine, true ) ) {
					$warnings[] = sprintf(
						/* translators: 1: header name, 2: header value. */
						__( 'A different %1$s header was received: %2$s. It comes from the server, a CDN, another plugin, or a page cache still holding an older policy. Browsers apply every policy they receive.', 'codo-content-security-policy' ),
						$name,
						mb_substr( (string) $value, 0, 300 )
					);
				}
			}
		}

		$size = 0;
		foreach ( $ours as $name => $values ) {
			foreach ( $values as $value ) {
				$size += strlen( $name ) + strlen( $value ) + 4;
			}
		}
		if ( $size > 4096 ) {
			$warnings[] = __( 'The policy headers are over 4 KB. NGINX with default FastCGI buffers can fail with "upstream sent too big header" (502). Remove unused sources or raise fastcgi_buffer_size.', 'codo-content-security-policy' );
		}
		return $warnings;
	}

	/**
	 * A policy without its report-uri/report-to parts (the scanned page may
	 * be cached from before the collection window changed).
	 *
	 * @param string $value Header value.
	 * @return string
	 */
	public static function without_reporting( $value ) {
		$parts = array_filter(
			array_map( 'trim', explode( ';', (string) $value ) ),
			static function ( $part ) {
				return '' !== $part && 0 !== strpos( $part, 'report-uri ' ) && 0 !== strpos( $part, 'report-to ' );
			}
		);
		return implode( '; ', $parts );
	}

	/**
	 * Drop query and fragment (they may carry tokens).
	 *
	 * @param string $url URL.
	 * @return string
	 */
	private static function strip_query( $url ) {
		return (string) preg_replace( '/[?#].*$/', '', $url );
	}

	/**
	 * A result skeleton.
	 *
	 * @param string $url     URL.
	 * @param string $context Context.
	 * @param string $status  ok, issues or error.
	 * @param string $error   Error message.
	 * @return array{url: string, context: string, time: int, status: string, error: string, issues: array<int, mixed>, draft: array<int, mixed>, warnings: string[], checked: int}
	 */
	private function result( $url, $context, $status, $error = '' ) {
		return array(
			'url'      => $url,
			'context'  => $context,
			'time'     => time(),
			'status'   => $status,
			'error'    => $error,
			'issues'   => array(),
			'draft'    => array(),
			'warnings' => array(),
			'checked'  => 0,
		);
	}
}
