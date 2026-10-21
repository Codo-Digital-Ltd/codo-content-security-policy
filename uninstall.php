<?php
/**
 * Removes all Codo Content Security Policy data when the plugin is deleted.
 *
 * @package CodoDigital\Csp
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

if ( ! defined( 'CODO_CSP_FILE' ) ) {
	define( 'CODO_CSP_FILE', __DIR__ . '/codo-content-security-policy.php' );
}

require_once __DIR__ . '/src/Autoloader.php';
\CodoDigital\Csp\Autoloader::register( __DIR__ . '/src' );

/*
 * Multisite: clean every site (each has its own table and options), then the
 * network defaults.
 */
if ( is_multisite() ) {
	foreach ( get_sites(
		array(
			'fields' => 'ids',
			'number' => 0,
		)
	) as $codo_csp_site_id ) {
		switch_to_blog( $codo_csp_site_id );
		\CodoDigital\Csp\Plugin::uninstall();
		restore_current_blog();
	}
	\CodoDigital\Csp\Plugin::uninstall_network();
} else {
	\CodoDigital\Csp\Plugin::uninstall();
}
