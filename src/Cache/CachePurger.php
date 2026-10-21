<?php
/**
 * Purges page caches when the policy changes.
 *
 * @package CodoDigital\Csp
 */

namespace CodoDigital\Csp\Cache;

use CodoDigital\Csp\Settings\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Full-page caches store the response headers with the page (or serve
 * pages without PHP at all), so after a policy or mode change visitors keep
 * getting the old policy until the cache is purged. This calls the purge
 * function of common cache plugins once per request.
 */
class CachePurger {

	/**
	 * Settings.
	 *
	 * @var Settings
	 */
	private $settings;

	/**
	 * Whether a purge is already queued for this request.
	 *
	 * @var bool
	 */
	private $queued = false;

	/**
	 * Constructor.
	 *
	 * @param Settings $settings Settings.
	 */
	public function __construct( Settings $settings ) {
		$this->settings = $settings;
	}

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function register() {
		add_action( 'codo_csp_policy_changed', array( $this, 'queue' ) );
		add_action( 'codo_csp_mode_changed', array( $this, 'queue' ) );
	}

	/**
	 * Purge once at the end of the request (several rules may change at once).
	 *
	 * @return void
	 */
	public function queue() {
		if ( $this->queued || ! $this->settings->get( 'purge_caches' ) ) {
			return;
		}
		$this->queued = true;
		add_action( 'shutdown', array( $this, 'purge' ) );
	}

	/**
	 * Purge known page caches.
	 *
	 * @return string[] Caches purged.
	 */
	public function purge() {
		$purged = array();

		if ( function_exists( 'wp_cache_clear_cache' ) ) {
			wp_cache_clear_cache(); // WP Super Cache.
			$purged[] = 'wp-super-cache';
		}
		if ( function_exists( 'w3tc_flush_all' ) ) {
			w3tc_flush_all(); // W3 Total Cache.
			$purged[] = 'w3-total-cache';
		}
		if ( function_exists( 'rocket_clean_domain' ) ) {
			rocket_clean_domain(); // WP Rocket.
			$purged[] = 'wp-rocket';
		}
		if ( function_exists( 'sg_cachepress_purge_cache' ) ) {
			sg_cachepress_purge_cache(); // SiteGround Optimizer.
			$purged[] = 'siteground';
		}
		if ( function_exists( 'wpo_cache_flush' ) ) {
			wpo_cache_flush(); // WP-Optimize.
			$purged[] = 'wp-optimize';
		}

		// Plugins that purge on an action (no-ops when not installed).
		$actions = array(
			'litespeed_purge_all'       => 'litespeed',      // LiteSpeed Cache.
			'rt_nginx_helper_purge_all' => 'nginx-helper', // Nginx Helper (fastcgi_cache / Redis).
			'breeze_clear_all_cache'    => 'breeze',         // Breeze.
		);
		foreach ( $actions as $action => $name ) {
			if ( has_action( $action ) ) {
				do_action( $action ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.DynamicHooknameFound -- Other plugins' hooks.
				$purged[] = $name;
			}
		}

		/**
		 * Fires after the plugin purges page caches; hook in to purge a CDN
		 * or a cache it does not know about.
		 *
		 * @param string[] $purged Caches purged.
		 */
		do_action( 'codo_csp_purge_caches', $purged );
		return $purged;
	}
}
