<?php
/**
 * Tests for Capability.
 *
 * @package CodoDigital\Csp\Tests
 */

namespace CodoDigital\Csp\Tests\Unit\Admin;

use Brain\Monkey\Filters;
use CodoDigital\Csp\Admin\Capability;
use CodoDigital\Csp\Tests\TestCase;

class CapabilityTest extends TestCase {

	public function test_site_defaults_to_manage_options() {
		$this->assertSame( 'manage_options', Capability::site() );
	}

	public function test_site_is_filterable() {
		Filters\expectApplied( 'codo_csp_capability' )->once()->with( 'manage_options' )->andReturn( 'edit_csp' );
		$this->assertSame( 'edit_csp', Capability::site() );
	}

	/**
	 * @return array<string, array{0: mixed}>
	 */
	public function bad_values() {
		return array(
			'empty'  => array( '' ),
			'array'  => array( array( 'edit_posts' ) ),
			'null'   => array( null ),
			'true'   => array( true ),
			'number' => array( 7 ),
		);
	}

	/**
	 * @dataProvider bad_values
	 */
	public function test_site_falls_back_on_unusable_filter_values( $value ) {
		Filters\expectApplied( 'codo_csp_capability' )->once()->andReturn( $value );
		$this->assertSame( 'manage_options', Capability::site() );
	}

	public function test_network() {
		$this->assertSame( 'manage_network_options', Capability::network() );
	}
}
