<?php
/**
 * Tests for Policy.
 *
 * @package CodoDigital\Csp\Tests
 */

namespace CodoDigital\Csp\Tests\Unit\Policy;

use CodoDigital\Csp\Policy\Policy;
use CodoDigital\Csp\Tests\TestCase;

class PolicyTest extends TestCase {

	const SELF = 'https://www.example.com';

	/**
	 * Build a policy from a directive => sources map.
	 *
	 * @param array<string, string[]> $map Map.
	 * @return Policy
	 */
	private function policy( array $map ) {
		$rules = array();
		foreach ( $map as $d => $sources ) {
			foreach ( $sources as $s ) {
				$rules[] = array(
					'd' => $d,
					's' => $s,
				);
			}
		}
		return new Policy( $rules );
	}

	public function test_drops_invalid_and_duplicate_rules_and_fills_metadata() {
		$policy = new Policy(
			array(
				'nonsense',
				array( 'd' => 'img-src' ),
				array(
					'd' => 'sandbox',
					's' => 'x',
				),
				array(
					'd' => 'img-src',
					's' => '',
				),
				array(
					'd' => 'img-src',
					's' => array(),
				),
				array(
					'd' => 'img-src',
					's' => "'self'",
				),
				array(
					'd' => 'img-src',
					's' => "'self'",
					'o' => 'other',
				),
			)
		);
		$this->assertSame(
			array(
				array(
					'd' => 'img-src',
					's' => "'self'",
					'o' => 'manual',
					't' => 0,
					'n' => '',
				),
			),
			$policy->rules()
		);
	}

	public function test_lookup_helpers() {
		$policy = $this->policy(
			array(
				'img-src'    => array( "'self'", 'data:' ),
				'object-src' => array( "'none'" ),
			)
		);
		$this->assertTrue( $policy->has( 'img-src', 'data:' ) );
		$this->assertFalse( $policy->has( 'img-src', 'blob:' ) );
		$this->assertTrue( $policy->defines( 'object-src' ) );
		$this->assertFalse( $policy->defines( 'font-src' ) );
		$this->assertSame( array( "'self'", 'data:' ), $policy->sources( 'img-src' ) );
	}

	public function test_effective_follows_fallback_chains() {
		$policy = $this->policy(
			array(
				'default-src' => array( "'self'" ),
				'script-src'  => array( "'self'", 'https://cdn.example.com' ),
				'child-src'   => array( 'https://frames.example.com' ),
			)
		);
		$this->assertSame( array( "'self'", 'https://cdn.example.com' ), $policy->effective( 'script-src-elem' ) );
		$this->assertSame( array( "'self'" ), $policy->effective( 'img-src' ) );
		$this->assertSame( array( 'https://frames.example.com' ), $policy->effective( 'frame-src' ) );
		$this->assertSame( array( 'https://frames.example.com' ), $policy->effective( 'worker-src' ) );
		$this->assertNull( $policy->effective( 'form-action' ), 'Standalone directives do not fall back.' );
		$this->assertNull( ( new Policy() )->effective( 'img-src' ) );
	}

	public function test_effective_ignores_none_alongside_other_sources() {
		$policy = $this->policy( array( 'img-src' => array( "'none'", 'data:' ) ) );
		$this->assertSame( array( 'data:' ), $policy->effective( 'img-src' ) );
	}

	public function test_with_without_merge_diff() {
		$a = $this->policy( array( 'img-src' => array( "'self'" ) ) );
		$b = $a->with(
			array(
				'd' => 'img-src',
				's' => 'data:',
			)
		);
		$this->assertFalse( $a->has( 'img-src', 'data:' ), 'Policies are immutable.' );
		$this->assertTrue( $b->has( 'img-src', 'data:' ) );
		$this->assertFalse( $b->without( 'img-src', 'data:' )->has( 'img-src', 'data:' ) );
		$this->assertTrue( $b->without( 'img-src', 'data:' )->has( 'img-src', "'self'" ) );

		$merged = $a->merge( $this->policy( array( 'font-src' => array( 'data:' ) ) ) );
		$this->assertTrue( $merged->has( 'font-src', 'data:' ) );
		$this->assertTrue( $merged->has( 'img-src', "'self'" ) );

		$this->assertSame( array( 'data:' ), array_column( $b->diff( $a ), 's' ) );
		$this->assertSame( array(), $a->diff( $b ) );
	}

	public function test_without_directive() {
		$policy = $this->policy(
			array(
				'default-src'     => array( "'self'" ),
				'frame-ancestors' => array( "'self'", 'https://partner.example.com' ),
			)
		);
		$without = $policy->without_directive( 'frame-ancestors' );
		$this->assertFalse( $without->defines( 'frame-ancestors' ) );
		$this->assertTrue( $without->has( 'default-src', "'self'" ) );
		$this->assertSame( array( 0 ), array_keys( $without->rules() ), 'rules stay a list' );
		$this->assertTrue( $policy->defines( 'frame-ancestors' ), 'Policies are immutable.' );
		$this->assertSame( $policy->rules(), $policy->without_directive( 'img-src' )->rules() );
	}

	public function test_compile_orders_directives_and_drops_redundant_none() {
		$policy = $this->policy(
			array(
				'frame-ancestors' => array( "'self'" ),
				'img-src'         => array( "'none'", 'data:' ),
				'default-src'     => array( "'self'" ),
				'object-src'      => array( "'none'" ),
			)
		);
		$this->assertSame( "default-src 'self'; img-src data:; object-src 'none'; frame-ancestors 'self'", $policy->compile() );
		$this->assertSame(
			"default-src 'self'; img-src data:; object-src 'none'; frame-ancestors 'self'; upgrade-insecure-requests; report-to x",
			$policy->compile( true, array( 'report-to x' ) )
		);
		$this->assertSame( '', ( new Policy() )->compile() );
	}

	/**
	 * @dataProvider loosening_cases
	 */
	public function test_is_loosening_of( $old, $new, $expected ) {
		$this->assertSame( $expected, $this->policy( $new )->is_loosening_of( $this->policy( $old ) ) );
	}

	public function loosening_cases() {
		$base = array(
			'default-src' => array( "'self'" ),
			'script-src'  => array( "'self'", "'unsafe-inline'" ),
		);
		return array(
			'identical'                         => array( $base, $base, true ),
			'adding a source'                   => array( $base, array_merge( $base, array( 'script-src' => array( "'self'", "'unsafe-inline'", 'https://a.com' ) ) ), true ),
			'removing a source'                 => array( $base, array_merge( $base, array( 'script-src' => array( "'self'" ) ) ), false ),
			'new directive without inherited'   => array( $base, array_merge( $base, array( 'frame-src' => array( 'https://youtube.com' ) ) ), false ),
			'new directive with inherited'      => array( $base, array_merge( $base, array( 'frame-src' => array( "'self'", 'https://youtube.com' ) ) ), true ),
			'new standalone directive'          => array( $base, array_merge( $base, array( 'base-uri' => array( "'self'" ) ) ), false ),
			'removing a standalone directive'   => array( array_merge( $base, array( 'base-uri' => array( "'self'" ) ) ), $base, true ),
			'adding a hash cancels inline'      => array( $base, array_merge( $base, array( 'script-src' => array( "'self'", "'unsafe-inline'", "'sha256-abc'" ) ) ), false ),
			'adding strict-dynamic'             => array( $base, array_merge( $base, array( 'script-src' => array( "'self'", "'unsafe-inline'", "'strict-dynamic'" ) ) ), false ),
			'removing a hash restores inline'   => array( array_merge( $base, array( 'script-src' => array( "'self'", "'unsafe-inline'", "'sha256-abc'" ) ) ), $base, true ),
			'replacing none'                    => array( array( 'object-src' => array( "'none'" ) ), array( 'object-src' => array( 'https://a.com' ) ), true ),
			'removing none falls back'          => array( array_merge( $base, array( 'object-src' => array( "'none'" ) ) ), $base, true ),
			'setting none'                      => array( $base, array_merge( $base, array( 'img-src' => array( "'none'" ) ) ), false ),
			'removing default-src entirely'     => array( $base, array( 'script-src' => array( "'self'", "'unsafe-inline'" ) ), true ),
		);
	}

	public function test_allows_resources() {
		$policy = $this->policy(
			array(
				'default-src' => array( "'self'" ),
				'script-src'  => array( "'self'", 'https://cdn.example.com' ),
				'img-src'     => array( "'self'", 'data:' ),
			)
		);
		$this->assertTrue( $policy->allows( 'script-src-elem', 'https://cdn.example.com/a.js', self::SELF ) );
		$this->assertFalse( $policy->allows( 'script-src-elem', 'https://evil.com/a.js', self::SELF ) );
		$this->assertTrue( $policy->allows( 'img-src', 'data:', self::SELF ) );
		$this->assertFalse( $policy->allows( 'font-src', 'https://fonts.gstatic.com/f.woff2', self::SELF ) );
		$this->assertTrue( $policy->allows( 'form-action', 'https://anywhere.com/', self::SELF ), 'Unrestricted when absent.' );
	}

	public function test_strict_dynamic_ignores_hosts_for_scripts() {
		$policy = $this->policy( array( 'script-src' => array( "'strict-dynamic'", 'https://cdn.example.com' ) ) );
		$this->assertFalse( $policy->allows( 'script-src-elem', 'https://cdn.example.com/a.js', self::SELF ) );
	}

	public function test_allows_inline() {
		$this->assertTrue( ( new Policy() )->allows_inline( 'script-src-elem' ) );
		$this->assertTrue( $this->policy( array( 'script-src' => array( "'unsafe-inline'" ) ) )->allows_inline( 'script-src-attr' ) );
		$this->assertFalse( $this->policy( array( 'script-src' => array( "'self'" ) ) )->allows_inline( 'script-src-elem' ) );
		$this->assertFalse( $this->policy( array( 'script-src' => array( "'unsafe-inline'", "'sha256-abc'" ) ) )->allows_inline( 'script-src-elem' ) );
		$this->assertTrue( $this->policy( array( 'default-src' => array( "'self'" ), 'style-src' => array( "'unsafe-inline'" ) ) )->allows_inline( 'style-src-attr' ) );
	}
}
