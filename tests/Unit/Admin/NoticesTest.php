<?php
/**
 * Tests for Notices.
 *
 * @package CodoDigital\Csp\Tests
 */

namespace CodoDigital\Csp\Tests\Unit\Admin;

use Brain\Monkey\Functions;
use CodoDigital\Csp\Admin\Notices;
use CodoDigital\Csp\Tests\TestCase;

class NoticesTest extends TestCase {

	public function test_add_queues_per_user_and_render_prints_once() {
		$notices = new Notices();
		$notices->add( 'success', 'Saved <b>it</b>.' );
		$notices->add( 'bogus" onmouseover="x', 'Typed' );

		$this->assertSame(
			array(
				array(
					'type'    => 'success',
					'message' => 'Saved <b>it</b>.',
				),
				array(
					'type'    => 'info',
					'message' => 'Typed',
				),
			),
			$this->transients['codo_csp_notice_1']
		);

		ob_start();
		$notices->render();
		$html = ob_get_clean();

		$this->assertSame(
			'<div class="notice notice-success is-dismissible"><p>Saved &lt;b&gt;it&lt;/b&gt;.</p></div>'
			. '<div class="notice notice-info is-dismissible"><p>Typed</p></div>',
			$html
		);
		$this->assertArrayNotHasKey( 'codo_csp_notice_1', $this->transients );

		ob_start();
		$notices->render();
		$this->assertSame( '', ob_get_clean() );
	}

	public function test_every_type_is_kept() {
		$notices = new Notices();
		foreach ( array( 'success', 'warning', 'error', 'info' ) as $type ) {
			$notices->add( $type, $type );
		}
		$this->assertSame( array( 'success', 'warning', 'error', 'info' ), array_column( $this->transients['codo_csp_notice_1'], 'type' ) );
	}

	public function test_notices_are_per_user() {
		Functions\when( 'get_current_user_id' )->justReturn( 9 );
		( new Notices() )->add( 'error', 'x' );
		$this->assertArrayHasKey( 'codo_csp_notice_9', $this->transients );
		$this->assertArrayNotHasKey( 'codo_csp_notice_1', $this->transients );
	}

	public function test_corrupt_transient_is_replaced_and_not_rendered() {
		$this->transients['codo_csp_notice_1'] = 'garbage';

		ob_start();
		( new Notices() )->render();
		$this->assertSame( '', ob_get_clean() );

		( new Notices() )->add( 'warning', 'w' );
		$this->assertCount( 1, $this->transients['codo_csp_notice_1'] );
	}

	public function test_empty_list_renders_nothing() {
		$this->transients['codo_csp_notice_1'] = array();
		ob_start();
		( new Notices() )->render();
		$this->assertSame( '', ob_get_clean() );
	}
}
