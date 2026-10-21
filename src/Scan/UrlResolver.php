<?php
/**
 * Resolves relative URLs.
 *
 * @package CodoDigital\Csp
 */

namespace CodoDigital\Csp\Scan;

defined( 'ABSPATH' ) || exit;

/**
 * Minimal RFC 3986 reference resolution, enough for resource URLs.
 */
final class UrlResolver {

	/**
	 * Resolve $ref against $base.
	 *
	 * @param string $ref  Reference as written in HTML or CSS.
	 * @param string $base Absolute base URL.
	 * @return string Absolute URL, data:/blob: URL, or '' when not a resource (javascript:, about:, empty, fragment).
	 */
	public static function resolve( $ref, $base ) {
		$ref = trim( html_entity_decode( (string) $ref, ENT_QUOTES, 'UTF-8' ) );
		if ( '' === $ref || '#' === $ref[0] ) {
			return '';
		}

		if ( preg_match( '/^([a-z][a-z0-9+.\-]*):/i', $ref, $m ) ) {
			$scheme = strtolower( $m[1] );
			if ( in_array( $scheme, array( 'javascript', 'about', 'mailto', 'tel', 'sms' ), true ) ) {
				return '';
			}
			if ( in_array( $scheme, array( 'data', 'blob' ), true ) ) {
				return $scheme . ':';
			}
			return $ref;
		}

		$b = wp_parse_url( $base );
		if ( ! is_array( $b ) || empty( $b['scheme'] ) || empty( $b['host'] ) ) {
			return '';
		}
		$origin = $b['scheme'] . '://' . $b['host'] . ( isset( $b['port'] ) ? ':' . $b['port'] : '' );

		if ( 0 === strpos( $ref, '//' ) ) {
			return $b['scheme'] . ':' . $ref;
		}
		if ( '/' === $ref[0] ) {
			return $origin . self::remove_dots( (string) preg_replace( '/[?#].*$/', '', $ref ) ) . self::suffix( $ref );
		}
		if ( '?' === $ref[0] ) {
			return $origin . ( isset( $b['path'] ) ? $b['path'] : '/' ) . $ref;
		}

		$dir = isset( $b['path'] ) ? preg_replace( '~/[^/]*$~', '/', $b['path'] ) : '/';
		if ( '' === $dir ) {
			$dir = '/';
		}
		$path = (string) preg_replace( '/[?#].*$/', '', $ref );
		return $origin . self::remove_dots( $dir . $path ) . self::suffix( $ref );
	}

	/**
	 * Query and fragment of a reference.
	 *
	 * @param string $ref Reference.
	 * @return string
	 */
	private static function suffix( $ref ) {
		return preg_match( '/[?#].*$/', $ref, $m ) ? $m[0] : '';
	}

	/**
	 * Remove . and .. segments.
	 *
	 * @param string $path Path.
	 * @return string
	 */
	private static function remove_dots( $path ) {
		$out = array();
		foreach ( explode( '/', $path ) as $segment ) {
			if ( '.' === $segment ) {
				continue;
			}
			if ( '..' === $segment ) {
				if ( count( $out ) > 1 ) {
					array_pop( $out );
				}
				continue;
			}
			$out[] = $segment;
		}
		$result = implode( '/', $out );
		if ( preg_match( '~/\.\.?$~', $path ) ) {
			$result .= '/';
		}
		return '' === $result ? '/' : $result;
	}
}
