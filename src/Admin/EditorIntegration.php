<?php
/**
 * Shows scan results where content is edited.
 *
 * @package CodoDigital\Csp
 */

namespace CodoDigital\Csp\Admin;

use CodoDigital\Csp\Scan\ScanScheduler;

defined( 'ABSPATH' ) || exit;

/**
 * A CSP column in post lists, and a notice in the block or classic editor
 * when the last scan of the post found resources the policy does not allow.
 * Only users who can manage the policy see them.
 */
class EditorIntegration {

	const COLUMN = 'codo_csp';
	const SCRIPT = 'codo-csp-editor';

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function register() {
		add_action( 'admin_init', array( $this, 'register_columns' ) );
		add_action( 'enqueue_block_editor_assets', array( $this, 'block_editor_notice' ) );
		add_action( 'admin_notices', array( $this, 'classic_notice' ) );
	}

	/**
	 * Add the column to viewable post types.
	 *
	 * @return void
	 */
	public function register_columns() {
		if ( ! current_user_can( Capability::site() ) ) {
			return;
		}
		foreach ( get_post_types( array( 'public' => true ) ) as $type ) {
			if ( 'attachment' === $type || ! is_post_type_viewable( $type ) ) {
				continue;
			}
			add_filter( "manage_{$type}_posts_columns", array( $this, 'add_column' ) );
			add_action( "manage_{$type}_posts_custom_column", array( $this, 'render_column' ), 10, 2 );
		}
	}

	/**
	 * Add the column.
	 *
	 * @param array<string, string> $columns Columns.
	 * @return array<string, string>
	 */
	public function add_column( $columns ) {
		$columns[ self::COLUMN ] = __( 'CSP', 'codo-content-security-policy' );
		return $columns;
	}

	/**
	 * Render the column.
	 *
	 * @param string $column  Column.
	 * @param int    $post_id Post ID.
	 * @return void
	 */
	public function render_column( $column, $post_id ) {
		if ( self::COLUMN !== $column ) {
			return;
		}
		$result = get_post_meta( (int) $post_id, ScanScheduler::META, true );
		if ( ! is_array( $result ) || ! isset( $result['status'] ) ) {
			echo '<span aria-hidden="true">&mdash;</span><span class="screen-reader-text">' . esc_html__( 'Not scanned', 'codo-content-security-policy' ) . '</span>';
			return;
		}
		$url = admin_url( 'options-general.php?page=' . AdminPage::SLUG . '&tab=scan' );
		if ( 'ok' === $result['status'] ) {
			echo '<span title="' . esc_attr__( 'Every resource found is allowed', 'codo-content-security-policy' ) . '">&#10003;</span>';
		} elseif ( 'error' === $result['status'] ) {
			echo '<a href="' . esc_url( $url ) . '">' . esc_html__( 'Scan failed', 'codo-content-security-policy' ) . '</a>';
		} else {
			$count = count( (array) $result['issues'] ) + count( (array) $result['draft'] );
			/* translators: %d: number of problems. */
			echo '<a href="' . esc_url( $url ) . '">' . esc_html( sprintf( _n( '%d blocked', '%d blocked', $count, 'codo-content-security-policy' ), $count ) ) . '</a>';
		}
	}

	/**
	 * Message for a post's last scan, or '' when there is nothing to say.
	 *
	 * @param int $post_id Post ID.
	 * @return string
	 */
	public function message_for( $post_id ) {
		$result = get_post_meta( (int) $post_id, ScanScheduler::META, true );
		if ( ! is_array( $result ) || ! isset( $result['status'] ) || 'issues' !== $result['status'] ) {
			return '';
		}
		$sources = array();
		foreach ( array_merge( (array) $result['issues'], (array) $result['draft'] ) as $issue ) {
			$sources[] = ! empty( $issue['inline'] ) ? $issue['directive'] . ' (inline)' : $issue['source'];
		}
		return sprintf(
			/* translators: %s: list of sources. */
			__( 'Content Security Policy: when this page was last published, it loaded resources the policy does not allow: %s. Review them under Settings > Content Security Policy > Scan.', 'codo-content-security-policy' ),
			implode( ', ', array_unique( $sources ) )
		);
	}

	/**
	 * Notice in the block editor, through core's notices store (no
	 * libraries of our own).
	 *
	 * @return void
	 */
	public function block_editor_notice() {
		if ( ! current_user_can( Capability::site() ) ) {
			return;
		}
		$post = get_post();
		if ( ! $post ) {
			return;
		}
		$message = $this->message_for( $post->ID );
		if ( '' === $message ) {
			return;
		}
		wp_register_script( self::SCRIPT, false, array( 'wp-data', 'wp-notices', 'wp-dom-ready' ), CODO_CSP_VERSION, true );
		wp_enqueue_script( self::SCRIPT );
		wp_add_inline_script(
			self::SCRIPT,
			'wp.domReady(function(){wp.data.dispatch("core/notices").createWarningNotice(' . wp_json_encode( $message ) . ',{id:"codo-csp-scan",isDismissible:true});});'
		);
	}

	/**
	 * Notice in the classic editor.
	 *
	 * @return void
	 */
	public function classic_notice() {
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( ! $screen || 'post' !== $screen->base || ( method_exists( $screen, 'is_block_editor' ) && $screen->is_block_editor() ) || ! current_user_can( Capability::site() ) ) {
			return;
		}
		$post = get_post();
		if ( ! $post ) {
			return;
		}
		$message = $this->message_for( $post->ID );
		if ( '' !== $message ) {
			echo '<div class="notice notice-warning"><p>' . esc_html( $message ) . '</p></div>';
		}
	}
}
