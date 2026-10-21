<?php
/**
 * Tests for RateLimiter (transient and object-cache backends).
 *
 * @package CodoDigital\Csp\Tests
 */

namespace CodoDigital\Csp\Tests\Unit\Reports;

use Brain\Monkey\Filters;
use Brain\Monkey\Functions;
use CodoDigital\Csp\Reports\RateLimiter;
use CodoDigital\Csp\Tests\TestCase;

class RateLimiterTest extends TestCase {

	/** Start of a minute window. */
	const NOW = 1800000000;

	public function test_limit_defaults_and_is_filterable() {
		$this->assertSame( RateLimiter::LIMIT, ( new RateLimiter() )->limit() );

		Filters\expectApplied( 'codo_csp_report_rate_limit' )->once()->with( RateLimiter::LIMIT )->andReturn( '5' );
		$this->assertSame( 5, ( new RateLimiter() )->limit() );
	}

	public function test_limit_is_at_least_one() {
		Filters\expectApplied( 'codo_csp_report_rate_limit' )->andReturn( 0 );
		$this->assertSame( 1, ( new RateLimiter() )->limit() );
	}

	public function test_transient_counts_up_to_limit() {
		Functions\when( 'wp_using_ext_object_cache' )->justReturn( false );
		Filters\expectApplied( 'codo_csp_report_rate_limit' )->andReturn( 3 );
		$limiter = new RateLimiter();

		$this->assertTrue( $limiter->allow( self::NOW ) );
		$this->assertTrue( $limiter->allow( self::NOW + 10 ) );
		$this->assertTrue( $limiter->allow( self::NOW + 59 ) );
		$this->assertFalse( $limiter->allow( self::NOW + 59 ) );
		$this->assertSame(
			array(
				'w' => (int) floor( self::NOW / 60 ),
				'n' => 3,
			),
			$this->transients[ RateLimiter::TRANSIENT ]
		);
	}

	public function test_transient_window_rolls_over() {
		Functions\when( 'wp_using_ext_object_cache' )->justReturn( false );
		Filters\expectApplied( 'codo_csp_report_rate_limit' )->andReturn( 1 );
		$limiter = new RateLimiter();

		$this->assertTrue( $limiter->allow( self::NOW ) );
		$this->assertFalse( $limiter->allow( self::NOW + 1 ) );
		$this->assertTrue( $limiter->allow( self::NOW + 60 ) );
		$this->assertSame( 1, $this->transients[ RateLimiter::TRANSIENT ]['n'] );
		$this->assertSame( (int) floor( ( self::NOW + 60 ) / 60 ), $this->transients[ RateLimiter::TRANSIENT ]['w'] );
	}

	/**
	 * @dataProvider corrupt_states
	 */
	public function test_corrupt_transient_resets( $state ) {
		Functions\when( 'wp_using_ext_object_cache' )->justReturn( false );
		$this->transients[ RateLimiter::TRANSIENT ] = $state;

		$this->assertTrue( ( new RateLimiter() )->allow( self::NOW ) );
		$this->assertSame( 1, $this->transients[ RateLimiter::TRANSIENT ]['n'] );
	}

	public function corrupt_states() {
		return array(
			'string'       => array( 'garbage' ),
			'missing n'    => array( array( 'w' => (int) floor( self::NOW / 60 ) ) ),
			'missing w'    => array( array( 'n' => 1000 ) ),
			'stale window' => array(
				array(
					'w' => 1,
					'n' => 1000,
				),
			),
		);
	}

	public function test_defaults_to_current_time() {
		Functions\when( 'wp_using_ext_object_cache' )->justReturn( false );
		$this->assertTrue( ( new RateLimiter() )->allow() );
		$this->assertEqualsWithDelta( (int) floor( time() / 60 ), $this->transients[ RateLimiter::TRANSIENT ]['w'], 1 );
	}

	public function test_object_cache_counts_per_window() {
		Functions\when( 'wp_using_ext_object_cache' )->justReturn( true );
		Filters\expectApplied( 'codo_csp_report_rate_limit' )->andReturn( 2 );
		$key   = 'rate_' . (int) floor( self::NOW / 60 );
		$count = 0;
		Functions\expect( 'wp_cache_add' )->times( 3 )->with( $key, 0, RateLimiter::GROUP, 120 );
		Functions\expect( 'wp_cache_incr' )->times( 3 )->with( $key, 1, RateLimiter::GROUP )->andReturnUsing(
			static function () use ( &$count ) {
				return ++$count;
			}
		);

		$limiter = new RateLimiter();
		$this->assertTrue( $limiter->allow( self::NOW ) );
		$this->assertTrue( $limiter->allow( self::NOW ) );
		$this->assertFalse( $limiter->allow( self::NOW ) );
		$this->assertArrayNotHasKey( RateLimiter::TRANSIENT, $this->transients );
	}

	public function test_object_cache_failure_refuses() {
		Functions\when( 'wp_using_ext_object_cache' )->justReturn( true );
		Functions\when( 'wp_cache_add' )->justReturn( false );
		Functions\when( 'wp_cache_incr' )->justReturn( false );
		$this->assertFalse( ( new RateLimiter() )->allow( self::NOW ) );
	}
}
