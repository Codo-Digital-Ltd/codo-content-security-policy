<?php
/**
 * Tests for the plugin's autoloader.
 *
 * @package CodoDigital\Csp\Tests
 */

namespace CodoDigital\Csp\Tests\Unit;

use CodoDigital\Csp\Autoloader;
use CodoDigital\Csp\Tests\TestCase;

class AutoloaderTest extends TestCase {

	public function test_loads_plugin_classes() {
		$this->assertTrue( Autoloader::load( 'CodoDigital\\Csp\\Policy\\Directives' ) );
	}

	public function test_ignores_other_namespaces() {
		$this->assertFalse( Autoloader::load( 'Vendor\\Thing' ) );
		$this->assertFalse( Autoloader::load( 'CodoDigital\\CspExtra\\Thing' ) );
		$this->assertFalse( Autoloader::load( 'codo_digital\\csp\\Plugin' ) );
	}

	public function test_rejects_path_traversal_and_odd_characters() {
		$this->assertFalse( Autoloader::load( 'CodoDigital\\Csp\\..\\..\\etc\\passwd' ) );
		$this->assertFalse( Autoloader::load( 'CodoDigital\\Csp\\Foo/Bar' ) );
		$this->assertFalse( Autoloader::load( 'CodoDigital\\Csp\\' ) );
		$this->assertFalse( Autoloader::load( "CodoDigital\\Csp\\Plugin\0" ) );
	}

	public function test_register_is_idempotent() {
		$before = count( spl_autoload_functions() );
		Autoloader::register( dirname( __DIR__, 2 ) . '/src/' );
		$this->assertSame( $before, count( spl_autoload_functions() ) );
		$this->assertTrue( class_exists( 'CodoDigital\\Csp\\Policy\\Presets' ) );
	}

	public function test_missing_class_returns_false() {
		$this->assertFalse( Autoloader::load( 'CodoDigital\\Csp\\DoesNotExist' ) );
		$this->assertFalse( class_exists( 'CodoDigital\\Csp\\Nope\\Missing' ) );
	}
}
