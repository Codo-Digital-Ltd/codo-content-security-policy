<?php
/**
 * Tests for EditorIntegration.
 *
 * @package CodoDigital\Csp\Tests
 */

namespace CodoDigital\Csp\Tests\Unit\Admin;

use Brain\Monkey\Functions;
use CodoDigital\Csp\Admin\EditorIntegration;
use CodoDigital\Csp\Scan\ScanScheduler;

class EditorIntegrationTest extends AdminTestCase {

	/**
	 * Post meta by post ID.
	 *
	 * @var array<int, mixed>
	 */
	private $meta = array();

	/**
	 * The current post.
	 *
	 * @var object|null
	 */
	private $post = null;

	protected function setUp(): void {
		parent::setUp();
		Functions\stubs(
			array(
				'get_post_meta' => function ( $id, $key, $single ) {
					return ScanScheduler::META === $key && isset( $this->meta[ $id ] ) ? $this->meta[ $id ] : '';
				},
				'get_post'      => function () {
					return $this->post;
				},
			)
		);
	}

	private static function issues_result() {
		return array(
			'status' => 'issues',
			'issues' => array(
				array(
					'directive' => 'script-src-elem',
					'source'    => 'https://evil.example.com',
				),
				array(
					'directive' => 'style-src-attr',
					'inline'    => true,
					'source'    => '',
				),
			),
			'draft'  => array(
				array(
					'directive' => 'img-src',
					'source'    => 'https://evil.example.com',
				),
				array(
					'directive' => 'font-src',
					'source'    => 'https://fonts.<b>x</b>.com',
				),
			),
		);
	}

	private function column( $column, $post_id ) {
		ob_start();
		( new EditorIntegration() )->render_column( $column, $post_id );
		return ob_get_clean();
	}

	public function test_register() {
		$editor = new EditorIntegration();
		$editor->register();
		$this->assertNotFalse( has_action( 'admin_init', array( $editor, 'register_columns' ) ) );
		$this->assertNotFalse( has_action( 'enqueue_block_editor_assets', array( $editor, 'block_editor_notice' ) ) );
		$this->assertNotFalse( has_action( 'admin_notices', array( $editor, 'classic_notice' ) ) );
	}

	public function test_register_columns_for_viewable_types_only() {
		Functions\expect( 'get_post_types' )->once()->with( array( 'public' => true ) )->andReturn(
			array(
				'post'       => 'post',
				'page'       => 'page',
				'attachment' => 'attachment',
				'hidden'     => 'hidden',
			)
		);
		Functions\when( 'is_post_type_viewable' )->alias(
			static function ( $type ) {
				return 'hidden' !== $type;
			}
		);
		$editor = new EditorIntegration();

		$editor->register_columns();

		foreach ( array( 'post', 'page' ) as $type ) {
			$this->assertNotFalse( has_filter( "manage_{$type}_posts_columns", array( $editor, 'add_column' ) ), $type );
			$this->assertNotFalse( has_action( "manage_{$type}_posts_custom_column", array( $editor, 'render_column' ) ), $type );
		}
		foreach ( array( 'attachment', 'hidden' ) as $type ) {
			$this->assertFalse( has_filter( "manage_{$type}_posts_columns", array( $editor, 'add_column' ) ), $type );
			$this->assertFalse( has_action( "manage_{$type}_posts_custom_column", array( $editor, 'render_column' ) ), $type );
		}
	}

	public function test_register_columns_needs_the_capability() {
		$this->can = false;
		Functions\expect( 'get_post_types' )->never();
		( new EditorIntegration() )->register_columns();
		$this->assertFalse( has_filter( 'manage_post_posts_columns' ) );
	}

	public function test_add_column() {
		$this->assertSame(
			array(
				'title'    => 'Title',
				'codo_csp' => 'CSP',
			),
			( new EditorIntegration() )->add_column( array( 'title' => 'Title' ) )
		);
	}

	public function test_render_column_ignores_other_columns() {
		$this->meta[3] = array( 'status' => 'ok' );
		$this->assertSame( '', $this->column( 'title', 3 ) );
	}

	public function test_render_column_not_scanned() {
		$this->meta[4] = array( 'no-status' => true );
		$this->assertStringContainsString( 'Not scanned', $this->column( 'codo_csp', 3 ) );
		$this->assertStringContainsString( 'Not scanned', $this->column( 'codo_csp', '4' ) );
	}

	public function test_render_column_ok() {
		$this->meta[3] = array( 'status' => 'ok' );
		$this->assertSame( '<span title="Every resource found is allowed">&#10003;</span>', $this->column( 'codo_csp', 3 ) );
	}

	public function test_render_column_error() {
		$this->meta[3] = array( 'status' => 'error' );
		$this->assertSame( '<a href="https://www.example.com/wp-admin/options-general.php?page=codo-csp&tab=scan">Scan failed</a>', $this->column( 'codo_csp', 3 ) );
	}

	public function test_render_column_issues() {
		$this->meta[3] = self::issues_result();
		$this->assertSame( '<a href="https://www.example.com/wp-admin/options-general.php?page=codo-csp&tab=scan">4 blocked</a>', $this->column( 'codo_csp', 3 ) );
	}

	public function test_message_for() {
		$editor        = new EditorIntegration();
		$this->meta[3] = self::issues_result();
		$this->meta[4] = array( 'status' => 'ok' );
		$this->meta[5] = 'garbage';

		$this->assertSame(
			'Content Security Policy: when this page was last published, it loaded resources the policy does not allow: https://evil.example.com, style-src-attr (inline), https://fonts.<b>x</b>.com. Review them under Settings > Content Security Policy > Scan.',
			$editor->message_for( 3 )
		);
		$this->assertSame( '', $editor->message_for( 4 ) );
		$this->assertSame( '', $editor->message_for( 5 ) );
		$this->assertSame( '', $editor->message_for( 6 ) );
	}

	public function test_block_editor_notice_needs_the_capability() {
		$this->can = false;
		Functions\expect( 'get_post' )->never();
		Functions\expect( 'wp_enqueue_script' )->never();
		( new EditorIntegration() )->block_editor_notice();
		$this->assertTrue( true );
	}

	public function test_block_editor_notice_without_a_post() {
		Functions\expect( 'wp_enqueue_script' )->never();
		( new EditorIntegration() )->block_editor_notice();
		$this->assertTrue( true );
	}

	public function test_block_editor_notice_without_a_message() {
		$this->post    = (object) array( 'ID' => 4 );
		$this->meta[4] = array( 'status' => 'ok' );
		Functions\expect( 'wp_enqueue_script' )->never();
		( new EditorIntegration() )->block_editor_notice();
		$this->assertTrue( true );
	}

	public function test_block_editor_notice_enqueues_an_inline_script() {
		$this->post    = (object) array( 'ID' => 3 );
		$this->meta[3] = self::issues_result();
		$editor        = new EditorIntegration();
		$message       = $editor->message_for( 3 );

		Functions\expect( 'wp_register_script' )->once()->with( 'codo-csp-editor', false, array( 'wp-data', 'wp-notices', 'wp-dom-ready' ), CODO_CSP_VERSION, true );
		Functions\expect( 'wp_enqueue_script' )->once()->with( 'codo-csp-editor' );
		Functions\expect( 'wp_add_inline_script' )->once()->with(
			'codo-csp-editor',
			'wp.domReady(function(){wp.data.dispatch("core/notices").createWarningNotice(' . json_encode( $message ) . ',{id:"codo-csp-scan",isDismissible:true});});'
		);

		$editor->block_editor_notice();
	}

	private function classic( $screen ) {
		Functions\when( 'get_current_screen' )->justReturn( $screen );
		ob_start();
		( new EditorIntegration() )->classic_notice();
		return ob_get_clean();
	}

	public function test_classic_notice_without_a_screen() {
		$this->post    = (object) array( 'ID' => 3 );
		$this->meta[3] = self::issues_result();
		$this->assertSame( '', $this->classic( null ) );
	}

	public function test_classic_notice_skips_other_screens() {
		$this->post    = (object) array( 'ID' => 3 );
		$this->meta[3] = self::issues_result();
		$this->assertSame( '', $this->classic( (object) array( 'base' => 'edit' ) ) );
	}

	public function test_classic_notice_skips_the_block_editor() {
		$this->post    = (object) array( 'ID' => 3 );
		$this->meta[3] = self::issues_result();
		$screen        = new class() {
			public $base = 'post';
			public function is_block_editor() {
				return true;
			}
		};
		$this->assertSame( '', $this->classic( $screen ) );
	}

	public function test_classic_notice_needs_the_capability() {
		$this->can     = false;
		$this->post    = (object) array( 'ID' => 3 );
		$this->meta[3] = self::issues_result();
		$this->assertSame( '', $this->classic( (object) array( 'base' => 'post' ) ) );
	}

	public function test_classic_notice_without_a_post() {
		$this->assertSame( '', $this->classic( (object) array( 'base' => 'post' ) ) );
	}

	public function test_classic_notice_without_a_message() {
		$this->post    = (object) array( 'ID' => 4 );
		$this->meta[4] = array( 'status' => 'error' );
		$this->assertSame( '', $this->classic( (object) array( 'base' => 'post' ) ) );
	}

	public function test_classic_notice_prints_the_escaped_message() {
		$this->post    = (object) array( 'ID' => 3 );
		$this->meta[3] = self::issues_result();
		$screen        = new class() {
			public $base = 'post';
			public function is_block_editor() {
				return false;
			}
		};

		$html = $this->classic( $screen );

		$this->assertStringStartsWith( '<div class="notice notice-warning"><p>Content Security Policy: when this page', $html );
		$this->assertStringContainsString( 'https://fonts.&lt;b&gt;x&lt;/b&gt;.com', $html );
		$this->assertStringNotContainsString( '<b>', $html );
	}
}
