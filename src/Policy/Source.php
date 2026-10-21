<?php
/**
 * Validation, normalisation and matching of CSP source expressions.
 *
 * @package CodoDigital\Csp
 */

namespace CodoDigital\Csp\Policy;

defined( 'ABSPATH' ) || exit;

/**
 * Source expressions: keywords ('self'), hashes ('sha256-...'), schemes
 * (https:) and hosts ([scheme://]host[:port][/path]).
 */
final class Source {

	/**
	 * Keywords valid in any fetch directive.
	 */
	const GENERAL_KEYWORDS = array( "'self'", "'none'" );

	/**
	 * Keywords only meaningful for scripts.
	 */
	const SCRIPT_KEYWORDS = array( "'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'", "'strict-dynamic'", "'wasm-unsafe-eval'", "'report-sample'" );

	/**
	 * Keywords only meaningful for styles.
	 */
	const STYLE_KEYWORDS = array( "'unsafe-inline'", "'unsafe-hashes'", "'report-sample'" );

	/**
	 * Schemes that must never be allowed to run script.
	 */
	const UNSAFE_SCRIPT_SOURCES = array( '*', 'http:', 'https:', 'data:', 'blob:', 'filesystem:', 'javascript:' );

	/**
	 * Default ports, for matching.
	 */
	const DEFAULT_PORTS = array(
		'http'  => 80,
		'https' => 443,
		'ws'    => 80,
		'wss'   => 443,
	);

	/**
	 * Validate and normalise a source for a directive.
	 *
	 * Accepts keywords with or without quotes, hashes, schemes, hosts and
	 * pasted URLs (the query and fragment are dropped).
	 *
	 * @param string $directive Directive name.
	 * @param string $raw       User input.
	 * @return string Normalised source.
	 * @throws InvalidSourceException When invalid or unsafe.
	 */
	public static function normalise( $directive, $raw ) {
		if ( ! Directives::is_known( $directive ) ) {
			throw new InvalidSourceException( esc_html__( 'Unknown directive.', 'codo-content-security-policy' ) );
		}

		$value = trim( (string) $raw );
		if ( '' === $value ) {
			throw new InvalidSourceException( esc_html__( 'Enter a source.', 'codo-content-security-policy' ) );
		}
		if ( strlen( $value ) > 255 || preg_match( '/[\s;,"<>\\\\\x00-\x1f\x7f]/', $value ) ) {
			throw new InvalidSourceException( esc_html__( 'A source is a single value without spaces, commas or semicolons.', 'codo-content-security-policy' ) );
		}

		$keyword = self::keyword( $value );
		if ( null !== $keyword ) {
			return self::check_keyword( $directive, $keyword );
		}

		if ( preg_match( "/^'?(sha256|sha384|sha512)-([A-Za-z0-9+\\/_-]+={0,2})'?$/i", $value, $m ) ) {
			if ( ! Directives::is_script( $directive ) && ! Directives::is_style( $directive ) ) {
				throw new InvalidSourceException( esc_html__( 'Hashes only apply to script and style directives.', 'codo-content-security-policy' ) );
			}
			return "'" . strtolower( $m[1] ) . '-' . $m[2] . "'";
		}

		if ( preg_match( "/^'?nonce-/i", $value ) ) {
			throw new InvalidSourceException( esc_html__( 'Nonces change on every request, so they cannot be added as a fixed source. Use a hash instead.', 'codo-content-security-policy' ) );
		}

		if ( 0 === strpos( $value, "'" ) ) {
			throw new InvalidSourceException( esc_html__( 'Unknown keyword.', 'codo-content-security-policy' ) );
		}

		if ( preg_match( '/^[a-z][a-z0-9+.\-]*:$/i', $value ) ) {
			$source = strtolower( $value );
		} else {
			$source = self::normalise_host( $value );
		}

		if ( self::is_too_broad( $directive, $source ) ) {
			throw new InvalidSourceException(
				sprintf(
					/* translators: 1: source such as https:, 2: directive name. */
					esc_html__( '%1$s in %2$s would let a script be loaded from anywhere, which defeats the policy. Add the specific host instead.', 'codo-content-security-policy' ),
					esc_html( $source ),
					esc_html( $directive )
				)
			);
		}
		if ( 'javascript:' === $source ) {
			throw new InvalidSourceException( esc_html__( 'javascript: is not a valid source.', 'codo-content-security-policy' ) );
		}

		return $source;
	}

	/**
	 * Whether a source would let code load from anywhere in a directive that
	 * governs code: any host (*, https://*, *:*), any https:/http: URL, or
	 * data:/blob: URLs. default-src counts, because it governs scripts when
	 * script-src is absent. Workers may use blob: (WordPress's emoji loader
	 * starts one from a blob the page itself created).
	 *
	 * @param string $directive Directive.
	 * @param string $source    Normalised scheme or host source.
	 * @return bool
	 */
	private static function is_too_broad( $directive, $source ) {
		$code = array( 'default-src', 'script-src', 'script-src-elem', 'script-src-attr', 'object-src', 'worker-src', 'base-uri' );
		if ( ! in_array( $directive, $code, true ) ) {
			return false;
		}
		if ( 'worker-src' === $directive && 'blob:' === $source ) {
			return false;
		}
		if ( in_array( $source, self::UNSAFE_SCRIPT_SOURCES, true ) ) {
			return true;
		}
		// Host part "*": https://*, *:*, http://*:8080/path.
		return 1 === preg_match( '~^(?:[a-z][a-z0-9+.\-]*://)?\*(?::|/|$)~', $source );
	}

	/**
	 * Recognise a keyword typed with or without quotes.
	 *
	 * @param string $value Input.
	 * @return string|null Quoted, lower-case keyword.
	 */
	private static function keyword( $value ) {
		$bare = strtolower( trim( $value, "'" ) );
		$all  = array_merge( self::GENERAL_KEYWORDS, self::SCRIPT_KEYWORDS );
		$q    = "'" . $bare . "'";
		return in_array( $q, $all, true ) ? $q : null;
	}

	/**
	 * Check a keyword is meaningful in the directive.
	 *
	 * @param string $directive Directive.
	 * @param string $keyword   Quoted keyword.
	 * @return string
	 * @throws InvalidSourceException When not allowed.
	 */
	private static function check_keyword( $directive, $keyword ) {
		if ( in_array( $keyword, self::GENERAL_KEYWORDS, true ) ) {
			return $keyword;
		}
		$allowed = array();
		if ( Directives::is_script( $directive ) ) {
			$allowed = array_merge( $allowed, self::SCRIPT_KEYWORDS );
		}
		if ( Directives::is_style( $directive ) ) {
			$allowed = array_merge( $allowed, self::STYLE_KEYWORDS );
		}
		if ( ! in_array( $keyword, $allowed, true ) ) {
			throw new InvalidSourceException(
				sprintf(
					/* translators: 1: keyword, 2: directive. */
					esc_html__( '%1$s has no effect in %2$s.', 'codo-content-security-policy' ),
					esc_html( $keyword ),
					esc_html( $directive )
				)
			);
		}
		return $keyword;
	}

	/**
	 * Normalise a host source or pasted URL.
	 *
	 * @param string $value Input.
	 * @return string
	 * @throws InvalidSourceException When not a valid host source.
	 */
	private static function normalise_host( $value ) {
		$pattern = '~^(?:([a-z][a-z0-9+.\-]*)://)?(\*|(?:\*\.)?[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?)*)(?::(\d{1,5}|\*))?(/[^?#]*)?(?:[?#].*)?$~i';
		if ( ! preg_match( $pattern, $value, $m ) ) {
			throw new InvalidSourceException( esc_html__( 'Not a valid host, scheme or keyword. Examples: https://cdn.example.com, *.example.com, data:, \'self\'.', 'codo-content-security-policy' ) );
		}
		$scheme = isset( $m[1] ) ? strtolower( $m[1] ) : '';
		$host   = strtolower( $m[2] );
		$port   = isset( $m[3] ) ? $m[3] : '';
		$path   = isset( $m[4] ) ? $m[4] : '';

		if ( '' !== $port && '*' !== $port && ( (int) $port < 1 || (int) $port > 65535 ) ) {
			throw new InvalidSourceException( esc_html__( 'Invalid port.', 'codo-content-security-policy' ) );
		}
		if ( '' !== $scheme && isset( self::DEFAULT_PORTS[ $scheme ] ) && (string) self::DEFAULT_PORTS[ $scheme ] === $port ) {
			$port = '';
		}
		if ( '/' === $path ) {
			$path = '';
		}

		return ( '' !== $scheme ? $scheme . '://' : '' ) . $host . ( '' !== $port ? ':' . $port : '' ) . $path;
	}

	/**
	 * Whether a source has any effect in a directive (browsers ignore, for
	 * example, 'unsafe-inline' in img-src, which it can inherit from
	 * default-src).
	 *
	 * @param string $directive Directive.
	 * @param string $source    Normalised source.
	 * @return bool
	 */
	public static function is_meaningful( $directive, $source ) {
		if ( 0 !== strpos( $source, "'" ) || in_array( $source, self::GENERAL_KEYWORDS, true ) ) {
			return true;
		}
		$script = Directives::is_script( $directive );
		if ( self::is_hash( $source ) ) {
			return $script || Directives::is_style( $directive );
		}
		return ( $script && in_array( $source, self::SCRIPT_KEYWORDS, true ) ) || ( Directives::is_style( $directive ) && in_array( $source, self::STYLE_KEYWORDS, true ) );
	}

	/**
	 * Whether a source is a hash.
	 *
	 * @param string $source Normalised source.
	 * @return bool
	 */
	public static function is_hash( $source ) {
		return 1 === preg_match( "/^'sha(256|384|512)-/", $source );
	}

	/**
	 * Whether a source makes the browser ignore 'unsafe-inline'.
	 *
	 * @param string $source Normalised source.
	 * @return bool
	 */
	public static function cancels_unsafe_inline( $source ) {
		return self::is_hash( $source ) || "'strict-dynamic'" === $source || 0 === strpos( $source, "'nonce-" );
	}

	/**
	 * Risk notes for a source in a directive, for the admin screen.
	 *
	 * @param string $directive Directive.
	 * @param string $source    Normalised source.
	 * @return string Empty when unremarkable.
	 */
	public static function warning( $directive, $source ) {
		if ( "'unsafe-eval'" === $source ) {
			return __( 'Lets scripts turn strings into code. Only add it if something breaks without it.', 'codo-content-security-policy' );
		}
		if ( "'unsafe-inline'" === $source && Directives::is_script( $directive ) ) {
			return __( 'Inline scripts are allowed, so the policy does not stop injected inline scripts. Most WordPress sites need this.', 'codo-content-security-policy' );
		}
		if ( in_array( $source, array( '*', 'https:', 'http:' ), true ) ) {
			return __( 'Allows any host.', 'codo-content-security-policy' );
		}
		return '';
	}

	/**
	 * Whether $source allows $url.
	 *
	 * @param string $source Normalised source expression.
	 * @param string $url    Absolute URL, or a data:/blob: URL.
	 * @param string $page_origin   Origin of the protected page (scheme://host[:port]).
	 * @return bool
	 */
	public static function matches( $source, $url, $page_origin ) {
		$target = self::parse( $url );
		if ( null === $target ) {
			return false;
		}

		if ( "'self'" === $source ) {
			$origin = self::parse( $page_origin );
			if ( null === $origin || '' === $target['host'] || $target['host'] !== $origin['host'] ) {
				return false;
			}
			// 'self' also covers WebSockets to the same host (CSP Level 3).
			$self_schemes = array(
				'http'  => array( 'http', 'https', 'ws', 'wss' ),
				'https' => array( 'https', 'wss' ),
			);
			$schemes      = isset( $self_schemes[ $origin['scheme'] ] ) ? $self_schemes[ $origin['scheme'] ] : array( $origin['scheme'] );
			if ( ! in_array( $target['scheme'], $schemes, true ) ) {
				return false;
			}
			return $target['port'] === $origin['port'] || ( self::is_default_port( $origin ) && self::is_default_port( $target ) );
		}

		if ( 0 === strpos( $source, "'" ) ) {
			return false;
		}

		if ( preg_match( '/^([a-z][a-z0-9+.\-]*):$/', $source, $m ) ) {
			return self::scheme_matches( $m[1], $target['scheme'] );
		}

		if ( ! in_array( $target['scheme'], array( 'http', 'https', 'ws', 'wss' ), true ) ) {
			return false;
		}

		if ( '*' === $source ) {
			return true;
		}

		return self::matches_host( $source, $target, $page_origin );
	}

	/**
	 * Match a host source.
	 *
	 * @param string               $source Host source.
	 * @param array<string, mixed> $target Parsed URL.
	 * @param string               $page_origin   Page origin.
	 * @return bool
	 */
	private static function matches_host( $source, array $target, $page_origin ) {
		if ( ! preg_match( '~^(?:([a-z][a-z0-9+.\-]*)://)?([^:/]+)(?::(\d+|\*))?(/.*)?$~', $source, $m ) ) {
			return false;
		}
		$scheme = $m[1];
		$host   = $m[2];
		$port   = isset( $m[3] ) ? $m[3] : '';
		$path   = isset( $m[4] ) ? $m[4] : '';

		if ( '' !== $scheme ) {
			if ( ! self::scheme_matches( $scheme, $target['scheme'] ) ) {
				return false;
			}
		} else {
			$origin      = self::parse( $page_origin );
			$page_scheme = null !== $origin ? $origin['scheme'] : 'https';
			if ( ! self::scheme_matches( $page_scheme, $target['scheme'] ) ) {
				return false;
			}
		}

		if ( '*' !== $host ) {
			if ( 0 === strpos( $host, '*.' ) ) {
				$suffix = substr( $host, 1 );
				if ( strlen( $target['host'] ) <= strlen( $suffix ) || substr( $target['host'], -strlen( $suffix ) ) !== $suffix ) {
					return false;
				}
			} elseif ( $host !== $target['host'] ) {
				return false;
			}
		}

		if ( '*' !== $port ) {
			if ( '' === $port ) {
				$scheme_for_port = '' !== $scheme ? $scheme : $target['scheme'];
				$expected        = isset( self::DEFAULT_PORTS[ $scheme_for_port ] ) ? self::DEFAULT_PORTS[ $scheme_for_port ] : null;
				$upgraded        = isset( self::DEFAULT_PORTS[ $target['scheme'] ] ) ? self::DEFAULT_PORTS[ $target['scheme'] ] : null;
				if ( $target['port'] !== $expected && $target['port'] !== $upgraded ) {
					return false;
				}
			} elseif ( (int) $port !== $target['port'] ) {
				return false;
			}
		}

		if ( '' !== $path && '/' !== $path ) {
			if ( '/' === substr( $path, -1 ) ) {
				return 0 === strpos( $target['path'], $path );
			}
			return $target['path'] === $path;
		}
		return true;
	}

	/**
	 * Whether a parsed URL uses its scheme's default port.
	 *
	 * @param array<string, mixed> $parts Parsed URL.
	 * @return bool
	 */
	private static function is_default_port( array $parts ) {
		return isset( self::DEFAULT_PORTS[ $parts['scheme'] ] ) && self::DEFAULT_PORTS[ $parts['scheme'] ] === $parts['port'];
	}

	/**
	 * CSP Level 3 "scheme-part match": a scheme also matches its secure
	 * counterpart, and ws:/wss: cover http(s).
	 *
	 * @param string $expected Scheme in the source (or the page's scheme).
	 * @param string $actual   Scheme of the resource.
	 * @return bool
	 */
	public static function scheme_matches( $expected, $actual ) {
		$map = array(
			'http' => array( 'http', 'https' ),
			'ws'   => array( 'ws', 'wss', 'http', 'https' ),
			'wss'  => array( 'wss', 'https' ),
		);
		return $expected === $actual || ( isset( $map[ $expected ] ) && in_array( $actual, $map[ $expected ], true ) );
	}

	/**
	 * Parse a URL into scheme, host, port and path.
	 *
	 * @param string $url URL.
	 * @return array{scheme: string, host: string, port: int|null, path: string}|null
	 */
	public static function parse( $url ) {
		if ( ! preg_match( '/^([a-z][a-z0-9+.\-]*):/i', (string) $url, $m ) ) {
			return null;
		}
		$scheme = strtolower( $m[1] );
		if ( in_array( $scheme, array( 'data', 'blob', 'filesystem', 'mediastream' ), true ) ) {
			return array(
				'scheme' => $scheme,
				'host'   => '',
				'port'   => null,
				'path'   => '',
			);
		}
		$parts = wp_parse_url( $url );
		if ( ! is_array( $parts ) || empty( $parts['host'] ) ) {
			return null;
		}
		$port = isset( $parts['port'] ) ? (int) $parts['port'] : ( isset( self::DEFAULT_PORTS[ $scheme ] ) ? self::DEFAULT_PORTS[ $scheme ] : null );
		return array(
			'scheme' => $scheme,
			'host'   => strtolower( $parts['host'] ),
			'port'   => $port,
			'path'   => isset( $parts['path'] ) ? $parts['path'] : '/',
		);
	}

	/**
	 * The origin of a URL as a host source (scheme://host[:port]), or the
	 * scheme source for data:/blob: URLs.
	 *
	 * @param string $url URL.
	 * @return string|null
	 */
	public static function origin_of( $url ) {
		$parts = self::parse( $url );
		if ( null === $parts ) {
			return null;
		}
		if ( '' === $parts['host'] ) {
			return $parts['scheme'] . ':';
		}
		$default = isset( self::DEFAULT_PORTS[ $parts['scheme'] ] ) ? self::DEFAULT_PORTS[ $parts['scheme'] ] : null;
		return $parts['scheme'] . '://' . $parts['host'] . ( null !== $parts['port'] && $parts['port'] !== $default ? ':' . $parts['port'] : '' );
	}
}
