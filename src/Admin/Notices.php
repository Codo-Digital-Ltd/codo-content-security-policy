<?php
/**
 * One-time admin notices shown after a form post redirects.
 *
 * @package CodoDigital\Csp
 */

namespace CodoDigital\Csp\Admin;

defined( 'ABSPATH' ) || exit;

/**
 * Stores notices per user in a short-lived transient.
 */
class Notices {

	const PREFIX = 'codo_csp_notice_';

	/**
	 * Transient key for the current user.
	 *
	 * @return string
	 */
	private function key() {
		return self::PREFIX . get_current_user_id();
	}

	/**
	 * Queue a notice.
	 *
	 * @param string $type    success, warning, error or info.
	 * @param string $message Plain text.
	 * @return void
	 */
	public function add( $type, $message ) {
		$notices   = get_transient( $this->key() );
		$notices   = is_array( $notices ) ? $notices : array();
		$notices[] = array(
			'type'    => in_array( $type, array( 'success', 'warning', 'error', 'info' ), true ) ? $type : 'info',
			'message' => (string) $message,
		);
		set_transient( $this->key(), $notices, 5 * MINUTE_IN_SECONDS );
	}

	/**
	 * Print and clear queued notices.
	 *
	 * @return void
	 */
	public function render() {
		$notices = get_transient( $this->key() );
		if ( ! is_array( $notices ) || empty( $notices ) ) {
			return;
		}
		delete_transient( $this->key() );
		foreach ( $notices as $notice ) {
			printf(
				'<div class="notice notice-%1$s is-dismissible"><p>%2$s</p></div>',
				esc_attr( $notice['type'] ),
				esc_html( $notice['message'] )
			);
		}
	}
}
