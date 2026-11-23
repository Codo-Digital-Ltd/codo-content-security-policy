<?php
/**
 * How many bytes of response headers the server takes from PHP.
 *
 * @package CodoDigital\Csp
 */

namespace CodoDigital\Csp\Http;

defined( 'ABSPATH' ) || exit;

/**
 * Resolves the FastCGI header buffer size the policy headers must fit in,
 * and says whether they do.
 *
 * In order: the CODO_CSP_HEADER_BUFFER_SIZE constant, overridden by the
 * codo_csp_header_buffer_size filter; on NGINX, the smallest
 * fastcgi_buffer_size in the config files PHP can read; otherwise a default.
 *
 * Apache and LiteSpeed get 8 KB: Apache's mod_proxy_fcgi reads response
 * headers into an 8 KB buffer (ProxyIOBufferSize), mod_php has no such
 * buffer, and LiteSpeed's is larger, so 8 KB is the safe common floor.
 * Unknown servers are treated like NGINX, whose default is 4 KB on most
 * platforms.
 */
class BufferLimit {

	const NGINX_DEFAULT = 4096;
	const OTHER_DEFAULT = 8192;

	/**
	 * Bytes left for headers other than the policy (cookies, Link, cache
	 * headers and so on). Filterable with codo_csp_header_buffer_headroom.
	 */
	const HEADROOM = 1024;

	const TRANSIENT = 'codo_csp_nginx_buffer';
	const MAX_FILES = 50;
	const MAX_BYTES = 1048576;

	const SOURCE_CONFIGURED     = 'configured';
	const SOURCE_DETECTED       = 'detected';
	const SOURCE_NGINX_DEFAULT  = 'nginx-default';
	const SOURCE_SERVER_DEFAULT = 'server-default';

	/**
	 * NGINX config entry points. Relative includes resolve against the
	 * first one's directory, as NGINX does.
	 */
	const NGINX_CONFIGS = array(
		'/etc/nginx/nginx.conf',
		'/etc/nginx/conf.d/*.conf',
		'/etc/nginx/sites-enabled/*',
	);

	/**
	 * The buffer size and where it came from.
	 *
	 * @return array{0: int, 1: string} Bytes, and a SOURCE_* constant.
	 */
	public static function resolve() {
		$configured = defined( 'CODO_CSP_HEADER_BUFFER_SIZE' ) ? (int) CODO_CSP_HEADER_BUFFER_SIZE : 0;
		/**
		 * Filters the server's FastCGI header buffer size in bytes. Return 0
		 * to detect it.
		 *
		 * @param int $bytes CODO_CSP_HEADER_BUFFER_SIZE, or 0.
		 */
		$configured = (int) apply_filters( 'codo_csp_header_buffer_size', $configured );
		if ( $configured > 0 ) {
			return array( $configured, self::SOURCE_CONFIGURED );
		}

		$software = isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) ) : '';
		if ( false !== strpos( $software, 'apache' ) || false !== strpos( $software, 'litespeed' ) ) {
			return array( self::OTHER_DEFAULT, self::SOURCE_SERVER_DEFAULT );
		}
		if ( false !== strpos( $software, 'nginx' ) ) {
			$detected = get_transient( self::TRANSIENT );
			if ( false === $detected ) {
				$detected = self::detect( self::NGINX_CONFIGS );
				set_transient( self::TRANSIENT, $detected, 12 * HOUR_IN_SECONDS );
			}
			if ( (int) $detected > 0 ) {
				return array( (int) $detected, self::SOURCE_DETECTED );
			}
		}
		return array( self::NGINX_DEFAULT, self::SOURCE_NGINX_DEFAULT );
	}

	/**
	 * Whether headers of this size risk overflowing the buffer, and a
	 * message saying so either way.
	 *
	 * @param int $size Bytes of policy headers.
	 * @return array{0: bool, 1: string} Whether to warn, and the message.
	 */
	public static function check( $size ) {
		list( $limit, $source ) = self::resolve();
		/**
		 * Filters the bytes kept free for headers other than the policy.
		 *
		 * @param int $headroom Bytes.
		 * @param int $limit    Buffer size in bytes.
		 */
		$headroom = (int) apply_filters( 'codo_csp_header_buffer_headroom', self::HEADROOM, $limit );
		$labels   = array(
			self::SOURCE_CONFIGURED     => __( 'configured', 'codo-content-security-policy' ),
			self::SOURCE_DETECTED       => __( 'detected from nginx config', 'codo-content-security-policy' ),
			self::SOURCE_NGINX_DEFAULT  => __( 'assumed NGINX default', 'codo-content-security-policy' ),
			self::SOURCE_SERVER_DEFAULT => __( 'assumed default for this server', 'codo-content-security-policy' ),
		);

		if ( $size > $limit - $headroom ) {
			return array(
				true,
				sprintf(
					/* translators: 1: header size such as 4.1 KB, 2: buffer size such as 4 KB, 3: where the buffer size came from, such as "assumed NGINX default". */
					__( 'Policy headers are %1$s, close to or over this server\'s %2$s FastCGI header buffer (%3$s). Remove sources you no longer need, raise fastcgi_buffer_size, or set the real size with the codo_csp_header_buffer_size filter.', 'codo-content-security-policy' ),
					size_format( $size, 1 ),
					size_format( $limit ),
					$labels[ $source ]
				),
			);
		}
		return array(
			false,
			sprintf(
				/* translators: 1: header size such as 4.1 KB, 2: buffer size such as 32 KB, 3: where the buffer size came from, such as "detected from nginx config". */
				__( 'Policy headers are %1$s. This server\'s FastCGI header buffer is %2$s (%3$s), so this is within limits.', 'codo-content-security-policy' ),
				size_format( $size, 1 ),
				size_format( $limit ),
				$labels[ $source ]
			),
		);
	}

	/**
	 * The smallest fastcgi_buffer_size in the given NGINX config files and
	 * the files they include. Reads at most MAX_FILES files and MAX_BYTES.
	 *
	 * @param string[] $patterns Paths or glob patterns.
	 * @return int Bytes, or 0 if none was found.
	 */
	public static function detect( array $patterns ) {
		$prefix = dirname( $patterns[0] );
		$queue  = $patterns;
		$seen   = array();
		$sizes  = array();
		$budget = self::MAX_BYTES;
		$files  = 0;
		while ( $queue && $files < self::MAX_FILES && $budget > 0 ) {
			foreach ( self::expand( array_shift( $queue ) ) as $file ) {
				if ( isset( $seen[ $file ] ) || $files >= self::MAX_FILES || $budget <= 0 ) {
					continue;
				}
				$seen[ $file ] = true;
				++$files;
				$text = file_get_contents( $file, false, null, 0, $budget ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file.
				if ( false === $text ) {
					continue;
				}
				$budget -= strlen( $text );
				$text    = preg_replace( '/#[^\n]*/', '', $text );
				preg_match_all( '/\bfastcgi_buffer_size\s+(\d+[kKmM]?)\s*;/', $text, $found );
				foreach ( $found[1] as $value ) {
					$sizes[] = self::parse_size( $value );
				}
				preg_match_all( '/\binclude\s+([^\s;]+)\s*;/', $text, $found );
				foreach ( $found[1] as $include ) {
					$include = trim( $include, '"\'' );
					$queue[] = '/' === $include[0] ? $include : $prefix . '/' . $include;
				}
			}
		}
		$sizes = array_filter( $sizes );
		return $sizes ? min( $sizes ) : 0;
	}

	/**
	 * An NGINX size such as 32k, 1m or 4096 in bytes.
	 *
	 * @param string $value Size.
	 * @return int Bytes, or 0 if not a size.
	 */
	public static function parse_size( $value ) {
		if ( ! preg_match( '/^\s*(\d+)\s*([kKmM]?)\s*$/', (string) $value, $m ) ) {
			return 0;
		}
		$units = array(
			''  => 1,
			'k' => 1024,
			'm' => 1048576,
		);
		return (int) $m[1] * $units[ strtolower( $m[2] ) ];
	}

	/**
	 * Whether open_basedir lets PHP open a path. Same prefix rule as PHP.
	 *
	 * Shortcut: compares the path as written, so a symlink or ".." leading
	 * outside open_basedir can still raise a PHP warning; resolve with
	 * realpath() if that turns up on real hosts.
	 *
	 * @param string $path         Path.
	 * @param string $open_basedir The open_basedir setting.
	 * @return bool
	 */
	public static function path_allowed( $path, $open_basedir ) {
		if ( '' === (string) $open_basedir ) {
			return true;
		}
		foreach ( explode( PATH_SEPARATOR, $open_basedir ) as $dir ) {
			if ( '' !== $dir && 0 === strpos( $path, $dir ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Readable files matching a path or glob pattern.
	 *
	 * @param string $pattern Path or pattern.
	 * @return string[]
	 */
	private static function expand( $pattern ) {
		if ( ! self::path_allowed( $pattern, (string) ini_get( 'open_basedir' ) ) ) {
			return array();
		}
		$files = false === strpbrk( $pattern, '*?[' ) ? array( $pattern ) : glob( $pattern );
		return array_filter(
			$files ? $files : array(),
			static function ( $file ) {
				return is_file( $file ) && is_readable( $file );
			}
		);
	}
}
