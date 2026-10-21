<?php
/**
 * Tests for Directives: metadata, fallback chains and where new sources go.
 *
 * @package CodoDigital\Csp\Tests
 */

namespace CodoDigital\Csp\Tests\Unit\Policy;

use CodoDigital\Csp\Policy\Directives;
use CodoDigital\Csp\Policy\Policy;
use CodoDigital\Csp\Tests\TestCase;

class DirectivesTest extends TestCase {

	/**
	 * Policy defining the given directives with 'self'.
	 *
	 * @param string[] $directives Directives.
	 * @return Policy
	 */
	private function policy( array $directives ) {
		$rules = array();
		foreach ( $directives as $directive ) {
			$rules[] = array(
				'd' => $directive,
				's' => "'self'",
			);
		}
		return new Policy( $rules );
	}

	public function test_all_lists_fetch_then_standalone_directives() {
		$all = Directives::all();
		$this->assertSame( 'default-src', $all[0] );
		$this->assertSame( array( 'base-uri', 'form-action', 'frame-ancestors' ), array_slice( $all, -3 ) );
		$this->assertCount( count( Directives::CHAINS ) + count( Directives::STANDALONE ), $all );
		$this->assertSame( $all, array_values( array_unique( $all ) ) );
	}

	public function test_is_known() {
		$this->assertTrue( Directives::is_known( 'worker-src' ) );
		$this->assertTrue( Directives::is_known( 'frame-ancestors' ) );
		$this->assertFalse( Directives::is_known( 'report-uri' ) );
		$this->assertFalse( Directives::is_known( 'SCRIPT-SRC' ) );
		$this->assertFalse( Directives::is_known( '' ) );
	}

	public function test_is_fetch() {
		$this->assertTrue( Directives::is_fetch( 'img-src' ) );
		$this->assertTrue( Directives::is_fetch( 'default-src' ) );
		$this->assertFalse( Directives::is_fetch( 'base-uri' ) );
		$this->assertFalse( Directives::is_fetch( 'nonsense' ) );
	}

	public function test_chain() {
		$this->assertSame( array( 'worker-src', 'child-src', 'script-src', 'default-src' ), Directives::chain( 'worker-src' ) );
		$this->assertSame( array( 'frame-src', 'child-src', 'default-src' ), Directives::chain( 'frame-src' ) );
		$this->assertSame( array( 'default-src' ), Directives::chain( 'default-src' ) );
		$this->assertSame( array( 'form-action' ), Directives::chain( 'form-action' ), 'standalone directives chain to themselves' );
		$this->assertSame( array( 'unknown' ), Directives::chain( 'unknown' ) );
	}

	public function test_every_chain_starts_with_itself_and_ends_at_default_src() {
		foreach ( Directives::CHAINS as $directive => $chain ) {
			$this->assertSame( $directive, $chain[0] );
			$this->assertSame( 'default-src', $chain[ count( $chain ) - 1 ] );
		}
	}

	public function test_is_script() {
		foreach ( array( 'script-src', 'script-src-elem', 'script-src-attr', 'default-src' ) as $directive ) {
			$this->assertTrue( Directives::is_script( $directive ), $directive );
		}
		$this->assertFalse( Directives::is_script( 'style-src' ) );
		$this->assertFalse( Directives::is_script( 'worker-src' ) );
	}

	public function test_is_style() {
		foreach ( array( 'style-src', 'style-src-elem', 'style-src-attr', 'default-src' ) as $directive ) {
			$this->assertTrue( Directives::is_style( $directive ), $directive );
		}
		$this->assertFalse( Directives::is_style( 'script-src' ) );
		$this->assertFalse( Directives::is_style( 'font-src' ) );
	}

	/**
	 * @dataProvider targets
	 */
	public function test_target( array $defined, $directive, $expected ) {
		$this->assertSame( $expected, Directives::target( $this->policy( $defined ), $directive ) );
	}

	public function targets() {
		return array(
			'own directive defined'                    => array( array( 'default-src', 'img-src' ), 'img-src', 'img-src' ),
			'only default-src: never widened'          => array( array( 'default-src' ), 'img-src', 'img-src' ),
			'empty policy'                             => array( array(), 'font-src', 'font-src' ),
			'elem falls back to defined base'          => array( array( 'script-src' ), 'script-src-elem', 'script-src' ),
			'elem defined itself'                      => array( array( 'script-src', 'script-src-elem' ), 'script-src-elem', 'script-src-elem' ),
			'elem with only default-src goes to base'  => array( array( 'default-src' ), 'script-src-elem', 'script-src' ),
			'attr with nothing goes to base'           => array( array(), 'style-src-attr', 'style-src' ),
			'style elem with base defined'             => array( array( 'style-src' ), 'style-src-elem', 'style-src' ),
			'script attr with nothing goes to base'    => array( array(), 'script-src-attr', 'script-src' ),
			'frame-src falls back to child-src'        => array( array( 'child-src' ), 'frame-src', 'child-src' ),
			'frame-src without child-src stays itself' => array( array( 'default-src' ), 'frame-src', 'frame-src' ),
			'worker never widens script-src'           => array( array( 'script-src' ), 'worker-src', 'worker-src' ),
			'worker uses child-src'                    => array( array( 'child-src', 'script-src' ), 'worker-src', 'child-src' ),
			'default-src itself'                       => array( array( 'default-src' ), 'default-src', 'default-src' ),
			'standalone defined'                       => array( array( 'base-uri' ), 'base-uri', 'base-uri' ),
			'standalone undefined'                     => array( array(), 'form-action', 'form-action' ),
		);
	}

	public function test_describe_every_directive() {
		foreach ( Directives::all() as $directive ) {
			$this->assertNotSame( '', Directives::describe( $directive ), $directive );
		}
		$this->assertStringContainsString( 'clickjacking', Directives::describe( 'frame-ancestors' ) );
	}

	public function test_describe_unknown_is_empty() {
		$this->assertSame( '', Directives::describe( 'report-to' ) );
	}
}
