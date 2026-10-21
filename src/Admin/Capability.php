<?php
/**
 * Capabilities for managing the policy.
 *
 * @package CodoDigital\Csp
 */

namespace CodoDigital\Csp\Admin;

defined( 'ABSPATH' ) || exit;

/**
 * Who may manage what.
 */
final class Capability {

	/**
	 * Capability to manage this site's policy.
	 *
	 * @return string
	 */
	public static function site() {
		/**
		 * Filters the capability required to manage the site's policy.
		 *
		 * @param string $capability Capability.
		 */
		$capability = apply_filters( 'codo_csp_capability', 'manage_options' );
		return is_string( $capability ) && '' !== $capability ? $capability : 'manage_options';
	}

	/**
	 * Capability to manage network defaults (multisite).
	 *
	 * @return string
	 */
	public static function network() {
		return 'manage_network_options';
	}
}
