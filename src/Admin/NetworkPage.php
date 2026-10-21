<?php
/**
 * Network Admin > Settings > Content Security Policy (multisite).
 *
 * @package CodoDigital\Csp
 */

namespace CodoDigital\Csp\Admin;

use CodoDigital\Csp\Settings\PolicyStore;

defined( 'ABSPATH' ) || exit;

/**
 * Network defaults: a baseline merged into every site's policy. Sites can
 * add to it but not remove from it.
 */
class NetworkPage {

	const SLUG = 'codo-csp-network';

	/**
	 * Policies.
	 *
	 * @var PolicyStore
	 */
	private $store;

	/**
	 * Notices.
	 *
	 * @var Notices
	 */
	private $notices;

	/**
	 * Constructor.
	 *
	 * @param PolicyStore $store   Policies.
	 * @param Notices     $notices Notices.
	 */
	public function __construct( PolicyStore $store, Notices $notices ) {
		$this->store   = $store;
		$this->notices = $notices;
	}

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function register() {
		add_action( 'network_admin_menu', array( $this, 'add_menu' ) );
	}

	/**
	 * Add the menu item.
	 *
	 * @return void
	 */
	public function add_menu() {
		add_submenu_page(
			'settings.php',
			__( 'Content Security Policy', 'codo-content-security-policy' ),
			__( 'Content Security Policy', 'codo-content-security-policy' ),
			Capability::network(),
			self::SLUG,
			array( $this, 'render' )
		);
	}

	/**
	 * Render.
	 *
	 * @return void
	 */
	public function render() {
		if ( ! current_user_can( Capability::network() ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'codo-content-security-policy' ), 403 );
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Navigation only.
		$context = isset( $_GET['tab'] ) && 'login' === $_GET['tab'] ? 'login' : 'site';

		echo '<div class="wrap codo-csp"><h1>' . esc_html__( 'Content Security Policy: network defaults', 'codo-content-security-policy' ) . '</h1>';
		$this->notices->render();
		echo '<p>' . esc_html__( 'Sources added here are part of every site\'s policy. Site administrators can add their own sources but cannot remove these. Each site keeps its own mode (Report-Only or enforced) and reports.', 'codo-content-security-policy' ) . '</p>';
		echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'Removing a network default takes effect straight away on every site, including sites that enforce their policy. Sites do not get a draft for network changes.', 'codo-content-security-policy' ) . '</p></div>';

		echo '<nav class="nav-tab-wrapper">';
		foreach ( array(
			'site'  => __( 'Front end', 'codo-content-security-policy' ),
			'login' => __( 'Login page', 'codo-content-security-policy' ),
		) as $slug => $label ) {
			printf(
				'<a href="%1$s" class="nav-tab%2$s">%3$s</a>',
				esc_url( add_query_arg( 'tab', $slug, network_admin_url( 'settings.php?page=' . self::SLUG ) ) ),
				$slug === $context ? ' nav-tab-active' : '',
				esc_html( $label )
			);
		}
		echo '</nav>';

		( new PolicyView( $this->store ) )->render( $context, 'network' );
		echo '</div>';
	}
}
