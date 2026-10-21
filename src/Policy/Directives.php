<?php
/**
 * The CSP directives the plugin manages, and how they fall back.
 *
 * @package CodoDigital\Csp
 */

namespace CodoDigital\Csp\Policy;

defined( 'ABSPATH' ) || exit;

/**
 * Directive metadata (CSP Level 3).
 */
final class Directives {

	/**
	 * Fallback chains for fetch directives: the browser uses the first
	 * directive in the chain that the policy defines. Directives not listed
	 * here (base-uri, form-action, frame-ancestors) never fall back, so when
	 * they are absent nothing is restricted.
	 */
	const CHAINS = array(
		'default-src'     => array( 'default-src' ),
		'script-src'      => array( 'script-src', 'default-src' ),
		'script-src-elem' => array( 'script-src-elem', 'script-src', 'default-src' ),
		'script-src-attr' => array( 'script-src-attr', 'script-src', 'default-src' ),
		'style-src'       => array( 'style-src', 'default-src' ),
		'style-src-elem'  => array( 'style-src-elem', 'style-src', 'default-src' ),
		'style-src-attr'  => array( 'style-src-attr', 'style-src', 'default-src' ),
		'img-src'         => array( 'img-src', 'default-src' ),
		'font-src'        => array( 'font-src', 'default-src' ),
		'connect-src'     => array( 'connect-src', 'default-src' ),
		'media-src'       => array( 'media-src', 'default-src' ),
		'object-src'      => array( 'object-src', 'default-src' ),
		'manifest-src'    => array( 'manifest-src', 'default-src' ),
		'child-src'       => array( 'child-src', 'default-src' ),
		'frame-src'       => array( 'frame-src', 'child-src', 'default-src' ),
		'worker-src'      => array( 'worker-src', 'child-src', 'script-src', 'default-src' ),
	);

	/**
	 * Document and navigation directives (no fallback).
	 */
	const STANDALONE = array( 'base-uri', 'form-action', 'frame-ancestors' );

	/**
	 * Order directives appear in the header and the admin screen.
	 *
	 * @return string[]
	 */
	public static function all() {
		return array_merge( array_keys( self::CHAINS ), self::STANDALONE );
	}

	/**
	 * Whether a directive is one the plugin manages.
	 *
	 * @param string $directive Directive name.
	 * @return bool
	 */
	public static function is_known( $directive ) {
		return in_array( $directive, self::all(), true );
	}

	/**
	 * Whether the directive falls back to another when absent.
	 *
	 * @param string $directive Directive name.
	 * @return bool
	 */
	public static function is_fetch( $directive ) {
		return isset( self::CHAINS[ $directive ] );
	}

	/**
	 * Fallback chain for a directive (just itself for standalone ones).
	 *
	 * @param string $directive Directive name.
	 * @return string[]
	 */
	public static function chain( $directive ) {
		return isset( self::CHAINS[ $directive ] ) ? self::CHAINS[ $directive ] : array( $directive );
	}

	/**
	 * Whether the directive governs scripts (and so accepts script keywords).
	 *
	 * @param string $directive Directive name.
	 * @return bool
	 */
	public static function is_script( $directive ) {
		return in_array( $directive, array( 'script-src', 'script-src-elem', 'script-src-attr', 'default-src' ), true );
	}

	/**
	 * Whether the directive governs styles.
	 *
	 * @param string $directive Directive name.
	 * @return bool
	 */
	public static function is_style( $directive ) {
		return in_array( $directive, array( 'style-src', 'style-src-elem', 'style-src-attr', 'default-src' ), true );
	}

	/**
	 * The directive a new source should be added to so that it affects
	 * $directive: the first one in the chain the policy defines, except that
	 * default-src is never widened for one resource type (the base directive,
	 * e.g. script-src, is created instead).
	 *
	 * @param Policy $policy    Policy.
	 * @param string $directive Directive a resource was checked against.
	 * @return string
	 */
	public static function target( Policy $policy, $directive ) {
		$chain = self::chain( $directive );
		foreach ( $chain as $candidate ) {
			// Never widen default-src for one resource type, nor scripts for a worker.
			if ( 'default-src' === $candidate || ( 'worker-src' === $directive && 'script-src' === $candidate ) ) {
				break;
			}
			if ( $policy->defines( $candidate ) ) {
				return $candidate;
			}
		}
		// script-src-elem -> script-src, frame-src -> frame-src, img-src -> img-src.
		if ( count( $chain ) > 2 && in_array( $directive, array( 'script-src-elem', 'script-src-attr', 'style-src-elem', 'style-src-attr' ), true ) ) {
			return $chain[1];
		}
		return $directive;
	}

	/**
	 * Human description for the admin screen.
	 *
	 * @param string $directive Directive name.
	 * @return string
	 */
	public static function describe( $directive ) {
		$descriptions = array(
			'default-src'     => __( 'Fallback for any resource type without its own directive.', 'codo-content-security-policy' ),
			'script-src'      => __( 'JavaScript files, inline scripts and event handlers.', 'codo-content-security-policy' ),
			'script-src-elem' => __( 'Script elements only (overrides script-src for them).', 'codo-content-security-policy' ),
			'script-src-attr' => __( 'Inline event handlers such as onclick (overrides script-src for them).', 'codo-content-security-policy' ),
			'style-src'       => __( 'Stylesheets, style elements and style attributes.', 'codo-content-security-policy' ),
			'style-src-elem'  => __( 'Stylesheets and style elements only.', 'codo-content-security-policy' ),
			'style-src-attr'  => __( 'Inline style attributes only.', 'codo-content-security-policy' ),
			'img-src'         => __( 'Images and favicons.', 'codo-content-security-policy' ),
			'font-src'        => __( 'Web fonts.', 'codo-content-security-policy' ),
			'connect-src'     => __( 'fetch, XHR, WebSocket and beacon requests made by scripts.', 'codo-content-security-policy' ),
			'media-src'       => __( 'Audio and video.', 'codo-content-security-policy' ),
			'object-src'      => __( 'Plugins via object and embed. Best left as \'none\'.', 'codo-content-security-policy' ),
			'manifest-src'    => __( 'Web app manifests.', 'codo-content-security-policy' ),
			'child-src'       => __( 'Fallback for frames and workers.', 'codo-content-security-policy' ),
			'frame-src'       => __( 'Pages this site embeds in iframes (YouTube, maps, payment forms).', 'codo-content-security-policy' ),
			'worker-src'      => __( 'Web workers and service workers.', 'codo-content-security-policy' ),
			'base-uri'        => __( 'Allowed values for the base element.', 'codo-content-security-policy' ),
			'form-action'     => __( 'Where forms may submit to, including redirects after submitting (e.g. to a payment provider).', 'codo-content-security-policy' ),
			'frame-ancestors' => __( 'Sites allowed to embed this site in a frame (clickjacking protection).', 'codo-content-security-policy' ),
		);
		return isset( $descriptions[ $directive ] ) ? $descriptions[ $directive ] : '';
	}
}
