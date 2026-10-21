<?php
/**
 * Tests for CachePurger. Each test runs in its own process because the cache
 * plugins' purge functions, once defined, cannot be undefined.
 *
 * @package CodoDigital\Csp\Tests
 */

namespace CodoDigital\Csp\Tests\Unit\Cache;

use Brain\Monkey\Actions;
use Brain\Monkey\Functions;
use CodoDigital\Csp\Cache\CachePurger;
use CodoDigital\Csp\Settings\Settings;
use CodoDigital\Csp\Tests\TestCase;

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class CachePurgerTest extends TestCase {

	const FUNCTIONS = array(
		'wp_cache_clear_cache'      => 'wp-super-cache',
		'w3tc_flush_all'            => 'w3-total-cache',
		'rocket_clean_domain'       => 'wp-rocket',
		'sg_cachepress_purge_cache' => 'siteground',
		'wpo_cache_flush'           => 'wp-optimize',
	);

	const ACTIONS = array(
		'litespeed_purge_all'       => 'litespeed',
		'rt_nginx_helper_purge_all' => 'nginx-helper',
		'breeze_clear_all_cache'    => 'breeze',
	);

	private function purger( array $settings = array() ) {
		$this->options[ Settings::OPTION ] = $settings;
		return new CachePurger( new Settings() );
	}

	public function test_register_hooks() {
		$purger = $this->purger();
		$purger->register();
		$this->assertNotFalse( has_action( 'codo_csp_policy_changed', array( $purger, 'queue' ) ) );
		$this->assertNotFalse( has_action( 'codo_csp_mode_changed', array( $purger, 'queue' ) ) );
	}

	public function test_queue_adds_shutdown_purge_once() {
		$purger = $this->purger();
		Actions\expectAdded( 'shutdown' )->once()->with( array( $purger, 'purge' ) );
		$purger->queue();
		$purger->queue();
		$this->assertNotFalse( has_action( 'shutdown', array( $purger, 'purge' ) ) );
	}

	public function test_queue_does_nothing_when_setting_off() {
		$purger = $this->purger( array( 'purge_caches' => false ) );
		Actions\expectAdded( 'shutdown' )->never();
		$purger->queue();
		$this->assertFalse( has_action( 'shutdown', array( $purger, 'purge' ) ) );
	}

	public function test_purge_with_no_cache_plugins() {
		foreach ( array_keys( self::FUNCTIONS ) as $function ) {
			$this->assertFalse( function_exists( $function ), $function );
		}
		Actions\expectDone( 'litespeed_purge_all' )->never();
		Actions\expectDone( 'codo_csp_purge_caches' )->once()->with( array() );
		$this->assertSame( array(), $this->purger()->purge() );
	}

	public function test_purge_calls_every_known_cache() {
		foreach ( array_keys( self::FUNCTIONS ) as $function ) {
			Functions\expect( $function )->once()->withNoArgs();
		}
		foreach ( array_keys( self::ACTIONS ) as $action ) {
			add_action( $action, '__return_true' );
			Actions\expectDone( $action )->once();
		}
		$expected = array_merge( array_values( self::FUNCTIONS ), array_values( self::ACTIONS ) );
		Actions\expectDone( 'codo_csp_purge_caches' )->once()->with( $expected );

		$this->assertSame( $expected, $this->purger()->purge() );
	}

	public function test_purge_only_installed_caches() {
		Functions\expect( 'rocket_clean_domain' )->once();
		add_action( 'breeze_clear_all_cache', '__return_true' );
		Actions\expectDone( 'breeze_clear_all_cache' )->once();
		Actions\expectDone( 'litespeed_purge_all' )->never();
		Actions\expectDone( 'rt_nginx_helper_purge_all' )->never();

		$this->assertSame( array( 'wp-rocket', 'breeze' ), $this->purger()->purge() );
	}
}
