<?php
/**
 * Ready-made rule sets for common third-party services, and the defaults.
 *
 * @package CodoDigital\Csp
 */

namespace CodoDigital\Csp\Policy;

defined( 'ABSPATH' ) || exit;

/**
 * Presets and default policies.
 */
final class Presets {

	/**
	 * Presets, keyed by ID.
	 *
	 * @return array<string, array{label: string, rules: array<string, string[]>}>
	 */
	public static function all() {
		$presets = array(
			'google-analytics'   => array(
				'label' => __( 'Google Analytics 4 (gtag.js)', 'codo-content-security-policy' ),
				'rules' => array(
					'script-src'  => array( 'https://www.googletagmanager.com' ),
					'connect-src' => array( 'https://*.google-analytics.com', 'https://*.analytics.google.com', 'https://*.googletagmanager.com' ),
					'img-src'     => array( 'https://*.google-analytics.com', 'https://*.googletagmanager.com' ),
				),
			),
			'google-tag-manager' => array(
				'label' => __( 'Google Tag Manager (tags it loads need their own presets)', 'codo-content-security-policy' ),
				'rules' => array(
					'script-src'  => array( 'https://www.googletagmanager.com' ),
					'img-src'     => array( 'https://www.googletagmanager.com' ),
					'connect-src' => array( 'https://www.googletagmanager.com' ),
					'frame-src'   => array( 'https://www.googletagmanager.com' ),
				),
			),
			'google-fonts'       => array(
				'label' => __( 'Google Fonts', 'codo-content-security-policy' ),
				'rules' => array(
					'style-src' => array( 'https://fonts.googleapis.com' ),
					'font-src'  => array( 'https://fonts.gstatic.com' ),
				),
			),
			'google-maps'        => array(
				'label' => __( 'Google Maps embeds', 'codo-content-security-policy' ),
				'rules' => array(
					'frame-src' => array( 'https://www.google.com', 'https://maps.google.com' ),
				),
			),
			'recaptcha'          => array(
				'label' => __( 'Google reCAPTCHA', 'codo-content-security-policy' ),
				'rules' => array(
					'script-src' => array( 'https://www.google.com', 'https://www.gstatic.com', 'https://www.recaptcha.net' ), // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- A host the policy allows, not an asset this plugin loads.
					'frame-src'  => array( 'https://www.google.com', 'https://recaptcha.google.com', 'https://www.recaptcha.net' ),
				),
			),
			'turnstile'          => array(
				'label' => __( 'Cloudflare Turnstile', 'codo-content-security-policy' ),
				'rules' => array(
					'script-src' => array( 'https://challenges.cloudflare.com' ), // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- A host the policy allows, not an asset this plugin loads.
					'frame-src'  => array( 'https://challenges.cloudflare.com' ), // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- A host the policy allows, not an asset this plugin loads.
				),
			),
			'youtube'            => array(
				'label' => __( 'YouTube embeds', 'codo-content-security-policy' ),
				'rules' => array(
					'frame-src' => array( 'https://www.youtube.com', 'https://www.youtube-nocookie.com' ),
					'img-src'   => array( 'https://i.ytimg.com' ),
				),
			),
			'vimeo'              => array(
				'label' => __( 'Vimeo embeds', 'codo-content-security-policy' ),
				'rules' => array(
					'frame-src' => array( 'https://player.vimeo.com' ),
					'img-src'   => array( 'https://i.vimeocdn.com' ),
				),
			),
			'stripe'             => array(
				'label' => __( 'Stripe (Stripe.js and Checkout)', 'codo-content-security-policy' ),
				'rules' => array(
					// Address Element autocomplete loads Google Maps.
					'script-src'  => array( 'https://js.stripe.com', 'https://*.js.stripe.com', 'https://maps.googleapis.com' ),
					'frame-src'   => array( 'https://js.stripe.com', 'https://*.js.stripe.com', 'https://hooks.stripe.com' ),
					'connect-src' => array( 'https://api.stripe.com', 'https://maps.googleapis.com' ),
					'form-action' => array( 'https://checkout.stripe.com' ),
				),
			),
			'paypal'             => array(
				'label' => __( 'PayPal', 'codo-content-security-policy' ),
				'rules' => array(
					'script-src'  => array( 'https://www.paypal.com', 'https://*.paypal.com' ),
					'frame-src'   => array( 'https://www.paypal.com', 'https://*.paypal.com' ),
					'connect-src' => array( 'https://*.paypal.com' ),
					'img-src'     => array( 'https://*.paypalobjects.com', 'https://*.paypal.com' ),
					'form-action' => array( 'https://www.paypal.com', 'https://*.paypal.com' ),
				),
			),
			'gravatar'           => array(
				'label' => __( 'Gravatar avatars', 'codo-content-security-policy' ),
				'rules' => array(
					'img-src' => array( 'https://secure.gravatar.com', 'https://*.gravatar.com' ),
				),
			),
			'jetpack'            => array(
				'label' => __( 'Jetpack / WordPress.com (stats, image CDN)', 'codo-content-security-policy' ),
				'rules' => array(
					'script-src'  => array( 'https://stats.wp.com', 'https://*.wp.com' ),
					'img-src'     => array( 'https://*.wp.com', 'https://pixel.wp.com' ),
					'connect-src' => array( 'https://*.wp.com' ),
				),
			),
			'facebook-pixel'     => array(
				'label' => __( 'Meta (Facebook) Pixel', 'codo-content-security-policy' ),
				'rules' => array(
					'script-src'  => array( 'https://connect.facebook.net' ),
					'img-src'     => array( 'https://www.facebook.com' ),
					'connect-src' => array( 'https://www.facebook.com', 'https://connect.facebook.net' ),
					'frame-src'   => array( 'https://www.facebook.com' ),
				),
			),
			'hotjar'             => array(
				'label' => __( 'Hotjar', 'codo-content-security-policy' ),
				'rules' => array(
					'script-src'  => array( 'https://*.hotjar.com' ),
					'connect-src' => array( 'https://*.hotjar.com', 'https://*.hotjar.io', 'wss://*.hotjar.com' ),
					'img-src'     => array( 'https://*.hotjar.com' ),
					'font-src'    => array( 'https://*.hotjar.com' ),
					'style-src'   => array( 'https://*.hotjar.com' ),
					'frame-src'   => array( 'https://*.hotjar.com' ),
				),
			),
			'clarity'            => array(
				'label' => __( 'Microsoft Clarity', 'codo-content-security-policy' ),
				'rules' => array(
					'script-src'  => array( 'https://www.clarity.ms', 'https://*.clarity.ms' ),
					'connect-src' => array( 'https://*.clarity.ms' ),
					'img-src'     => array( 'https://*.clarity.ms', 'https://c.bing.com' ),
				),
			),
		);

		/**
		 * Filters the presets offered on the policy screen.
		 *
		 * @param array<string, array{label: string, rules: array<string, string[]>}> $presets Presets.
		 */
		$filtered = apply_filters( 'codo_csp_presets', $presets );
		return is_array( $filtered ) ? $filtered : $presets;
	}

	/**
	 * The policy a context starts with.
	 *
	 * Allowlist first: 'unsafe-inline' is kept for scripts and styles
	 * because almost every WordPress site prints inline scripts, and hashes
	 * or nonces do not survive full-page caching. The policy still blocks
	 * scripts from unlisted hosts, plugins, base-tag hijacking, form
	 * hijacking and framing by other sites.
	 *
	 * @param string $context site or login.
	 * @return array<string, string[]>
	 */
	public static function defaults( $context ) {
		$rules = array(
			'default-src'     => array( "'self'" ),
			'script-src'      => array( "'self'", "'unsafe-inline'" ),
			'style-src'       => array( "'self'", "'unsafe-inline'" ),
			// s.w.org serves core's emoji images; Gravatar serves avatars.
			'img-src'         => array( "'self'", 'data:', 'https://s.w.org', 'https://secure.gravatar.com' ), // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- A host the policy allows, not an asset this plugin loads.
			'font-src'        => array( "'self'", 'data:' ),
			'connect-src'     => array( "'self'" ),
			'frame-src'       => array( "'self'" ),
			// Core's emoji loader runs its feature test in a worker started from a blob.
			'worker-src'      => array( "'self'", 'blob:' ),
			'object-src'      => array( "'none'" ),
			'base-uri'        => array( "'self'" ),
			'form-action'     => array( "'self'" ),
			'frame-ancestors' => array( "'self'" ),
		);
		if ( 'login' === $context ) {
			unset( $rules['frame-src'] );
		}

		/**
		 * Filters the policy a context starts with on activation.
		 *
		 * @param array<string, string[]> $rules   Directive => sources.
		 * @param string                  $context site or login.
		 */
		$filtered = apply_filters( 'codo_csp_default_rules', $rules, $context );
		return is_array( $filtered ) ? $filtered : $rules;
	}

	/**
	 * Expand a directive => sources map into rules.
	 *
	 * @param array<string, string[]> $map    Map.
	 * @param string                  $origin Origin label.
	 * @param int                     $time   Timestamp.
	 * @return array<int, array{d: string, s: string, o: string, t: int, n: string}>
	 */
	public static function to_rules( array $map, $origin, $time ) {
		$rules = array();
		foreach ( $map as $directive => $sources ) {
			foreach ( (array) $sources as $source ) {
				try {
					$rules[] = array(
						'd' => (string) $directive,
						's' => Source::normalise( (string) $directive, (string) $source ),
						'o' => $origin,
						't' => (int) $time,
						'n' => '',
					);
				} catch ( InvalidSourceException $e ) {
					continue;
				}
			}
		}
		return $rules;
	}
}
