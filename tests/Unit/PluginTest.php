<?php
/**
 * Tests for Plugin: object graph, booting, hooks and lifecycle.
 *
 * @package CodoDigital\Csp\Tests
 */

namespace CodoDigital\Csp\Tests\Unit;

use Brain\Monkey\Functions;
use CodoDigital\Csp\Admin\AdminPage;
use CodoDigital\Csp\Admin\EditorIntegration;
use CodoDigital\Csp\Admin\FormHandler;
use CodoDigital\Csp\Admin\NetworkPage;
use CodoDigital\Csp\Admin\Notices;
use CodoDigital\Csp\Cache\CachePurger;
use CodoDigital\Csp\Http\HeaderSender;
use CodoDigital\Csp\Plugin;
use CodoDigital\Csp\Reports\RateLimiter;
use CodoDigital\Csp\Reports\ReportEndpoint;
use CodoDigital\Csp\Reports\ReportRepository;
use CodoDigital\Csp\Scan\Scanner;
use CodoDigital\Csp\Scan\ScanScheduler;
use CodoDigital\Csp\Settings\PolicyStore;
use CodoDigital\Csp\Settings\Settings;
use CodoDigital\Csp\Tests\TestCase;

class PluginTest extends TestCase {

	/**
	 * Database double.
	 *
	 * @var \Mockery\MockInterface
	 */
	private $wpdb;

	protected function setUp(): void {
		parent::setUp();
		Plugin::reset();
		unset( $_GET[ ReportEndpoint::QUERY_VAR ] );
		$this->wpdb         = \Mockery::mock( 'wpdb' );
		$this->wpdb->prefix = 'wp_';
		$this->wpdb->shouldReceive( 'prepare' )->andReturn( 'SQL' )->byDefault();
		$this->wpdb->shouldReceive( 'get_charset_collate' )->andReturn( '' )->byDefault();
		$GLOBALS['wpdb'] = $this->wpdb;
	}

	protected function tearDown(): void {
		Plugin::reset();
		unset( $GLOBALS['wpdb'], $_GET[ ReportEndpoint::QUERY_VAR ] );
		parent::tearDown();
	}

	/**
	 * Plugin with mocked services.
	 *
	 * @return array{0: Plugin, 1: array<string, \Mockery\MockInterface>}
	 */
	private function mocked() {
		$services = array(
			'settings'  => \Mockery::mock( Settings::class ),
			'store'     => \Mockery::mock( PolicyStore::class ),
			'headers'   => \Mockery::mock( HeaderSender::class ),
			'reports'   => \Mockery::mock( ReportRepository::class ),
			'endpoint'  => \Mockery::mock( ReportEndpoint::class ),
			'scheduler' => \Mockery::mock( ScanScheduler::class ),
			'purger'    => \Mockery::mock( CachePurger::class ),
			'handler'   => \Mockery::mock( FormHandler::class ),
			'admin'     => \Mockery::mock( AdminPage::class ),
			'network'   => \Mockery::mock( NetworkPage::class ),
			'editor'    => \Mockery::mock( EditorIntegration::class ),
		);
		return array( new Plugin( $services ), $services );
	}

	/**
	 * Expect the hooks every request registers, on an installed site.
	 *
	 * @param array<string, \Mockery\MockInterface> $services Services.
	 * @return void
	 */
	private function expect_common( array $services ) {
		$services['reports']->shouldReceive( 'maybe_install' )->once();
		$services['store']->shouldReceive( 'seed' )->once()->andReturn( false );
		$services['endpoint']->shouldReceive( 'maybe_handle' )->once();
		$services['headers']->shouldReceive( 'register' )->once();
		$services['scheduler']->shouldReceive( 'register' )->once();
		$services['purger']->shouldReceive( 'register' )->once();
		Functions\when( 'wp_next_scheduled' )->justReturn( 123 );
	}

	public function test_create_builds_the_object_graph() {
		$plugin = Plugin::create();
		$this->assertInstanceOf( Settings::class, $plugin->get( 'settings' ) );
		$this->assertInstanceOf( PolicyStore::class, $plugin->get( 'store' ) );
		$this->assertInstanceOf( HeaderSender::class, $plugin->get( 'headers' ) );
		$this->assertInstanceOf( ReportRepository::class, $plugin->get( 'reports' ) );
		$this->assertInstanceOf( ReportEndpoint::class, $plugin->get( 'endpoint' ) );
		$this->assertInstanceOf( Scanner::class, $plugin->get( 'scanner' ) );
		$this->assertInstanceOf( ScanScheduler::class, $plugin->get( 'scheduler' ) );
		$this->assertInstanceOf( CachePurger::class, $plugin->get( 'purger' ) );
		$this->assertInstanceOf( Notices::class, $plugin->get( 'notices' ) );
		$this->assertInstanceOf( FormHandler::class, $plugin->get( 'handler' ) );
		$this->assertInstanceOf( AdminPage::class, $plugin->get( 'admin' ) );
		$this->assertInstanceOf( NetworkPage::class, $plugin->get( 'network' ) );
		$this->assertInstanceOf( EditorIntegration::class, $plugin->get( 'editor' ) );
		$this->assertSame( 'wp_codo_csp_reports', $plugin->get( 'reports' )->table() );
	}

	public function test_boot_registers_once_and_reset_forgets() {
		$this->options[ ReportRepository::DB_OPTION ] = ReportRepository::DB_VERSION;
		$this->options[ PolicyStore::OPTION ]         = array();
		Functions\when( 'is_admin' )->justReturn( false );
		Functions\expect( 'wp_next_scheduled' )->twice()->with( Plugin::PURGE_HOOK )->andReturn( 123 );

		$first  = Plugin::boot();
		$second = Plugin::boot();
		$this->assertSame( $first, $second );
		$this->assertNotFalse( has_action( 'send_headers', array( $first->get( 'headers' ), 'send_front' ) ) );
		$this->assertNotFalse( has_action( Plugin::PURGE_HOOK, array( $first, 'purge_reports' ) ) );
		$this->assertNotFalse( has_action( 'codo_csp_policy_changed', array( $first->get( 'purger' ), 'queue' ) ) );
		$this->assertNotFalse( has_action( ScanScheduler::URL_HOOK, array( $first->get( 'scheduler' ), 'scan_url' ) ) );
		$this->assertFalse( has_action( 'admin_menu' ), 'no admin hooks outside wp-admin' );

		Plugin::reset();
		$this->assertNotSame( $first, Plugin::boot() );
	}

	public function test_register_front_end() {
		list( $plugin, $services ) = $this->mocked();
		$this->expect_common( $services );
		Functions\when( 'is_admin' )->justReturn( false );
		Functions\expect( 'wp_schedule_event' )->never();
		$services['handler']->shouldReceive( 'register' )->never();
		$services['admin']->shouldReceive( 'register' )->never();

		$plugin->register();
		$this->assertNotFalse( has_action( Plugin::PURGE_HOOK, array( $plugin, 'purge_reports' ) ) );
	}

	public function test_register_admin_single_site() {
		list( $plugin, $services ) = $this->mocked();
		$this->expect_common( $services );
		Functions\when( 'is_admin' )->justReturn( true );
		Functions\when( 'is_multisite' )->justReturn( false );
		$services['handler']->shouldReceive( 'register' )->once();
		$services['admin']->shouldReceive( 'register' )->once();
		$services['editor']->shouldReceive( 'register' )->once();
		$services['network']->shouldReceive( 'register' )->never();

		$plugin->register();
		$this->assertNotFalse( has_action( Plugin::PURGE_HOOK ) );
	}

	public function test_register_admin_multisite() {
		list( $plugin, $services ) = $this->mocked();
		$this->expect_common( $services );
		Functions\when( 'is_admin' )->justReturn( true );
		Functions\when( 'is_multisite' )->justReturn( true );
		$services['handler']->shouldReceive( 'register' )->once();
		$services['admin']->shouldReceive( 'register' )->once();
		$services['editor']->shouldReceive( 'register' )->once();
		$services['network']->shouldReceive( 'register' )->once();

		$plugin->register();
		$this->assertNotFalse( has_action( Plugin::PURGE_HOOK ) );
	}

	public function test_ensure_installed_when_already_seeded() {
		list( $plugin, $services ) = $this->mocked();
		$services['reports']->shouldReceive( 'maybe_install' )->once();
		$services['store']->shouldReceive( 'seed' )->once()->andReturn( false );
		$services['settings']->shouldReceive( 'collect_for' )->never();
		Functions\expect( 'wp_schedule_single_event' )->never();

		$this->assertFalse( $plugin->ensure_installed() );
	}

	public function test_ensure_installed_first_install() {
		list( $plugin, $services ) = $this->mocked();
		$services['reports']->shouldReceive( 'maybe_install' )->once();
		$services['store']->shouldReceive( 'seed' )->once()->andReturn( true );
		$services['settings']->shouldReceive( 'collect_for' )->once()->with( 7 );
		$services['settings']->shouldReceive( 'report_token' )->once()->andReturn( 'tok' );
		Functions\expect( 'wp_next_scheduled' )->once()->with( ScanScheduler::URL_HOOK, array( 'https://www.example.com/' ) )->andReturn( false );
		Functions\expect( 'wp_schedule_single_event' )->once()->with( \Mockery::type( 'int' ), ScanScheduler::URL_HOOK, array( 'https://www.example.com/' ) );

		$this->assertTrue( $plugin->ensure_installed() );
	}

	public function test_ensure_installed_first_install_with_scan_already_queued() {
		list( $plugin, $services ) = $this->mocked();
		$services['reports']->shouldReceive( 'maybe_install' )->once();
		$services['store']->shouldReceive( 'seed' )->once()->andReturn( true );
		$services['settings']->shouldReceive( 'collect_for' )->once()->with( 7 );
		$services['settings']->shouldReceive( 'report_token' )->once();
		Functions\when( 'wp_next_scheduled' )->justReturn( 999 );
		Functions\expect( 'wp_schedule_single_event' )->never();

		$this->assertTrue( $plugin->ensure_installed() );
	}

	public function test_ensure_installed_with_real_services_seeds_and_collects() {
		$this->options[ ReportRepository::DB_OPTION ] = ReportRepository::DB_VERSION;
		Functions\when( 'wp_generate_password' )->justReturn( 'Token123' );
		Functions\when( 'wp_next_scheduled' )->justReturn( false );
		Functions\expect( 'wp_schedule_single_event' )->once();

		$plugin = Plugin::create();
		$this->assertTrue( $plugin->ensure_installed() );
		$this->assertTrue( $plugin->get( 'store' )->is_seeded() );
		$this->assertTrue( $plugin->get( 'settings' )->is_collecting() );
		$this->assertSame( 'Token123', $this->options[ Settings::OPTION ]['report_token'] );
		$this->assertFalse( $plugin->ensure_installed(), 'second run is a no-op' );
	}

	public function test_purge_reports() {
		list( $plugin, $services ) = $this->mocked();
		$services['reports']->shouldReceive( 'purge_older_than' )->once()->with( Plugin::REPORT_MAX_AGE )->andReturn( 4 );
		$this->assertSame( 4, $plugin->purge_reports() );
	}

	public function test_schedule_purge_when_missing() {
		Functions\expect( 'wp_next_scheduled' )->once()->with( Plugin::PURGE_HOOK )->andReturn( false );
		Functions\expect( 'wp_schedule_event' )->once()->with( \Mockery::type( 'int' ), 'daily', Plugin::PURGE_HOOK );
		Plugin::schedule_purge();
		$this->assertTrue( true );
	}

	public function test_schedule_purge_when_already_scheduled() {
		Functions\when( 'wp_next_scheduled' )->justReturn( 123 );
		Functions\expect( 'wp_schedule_event' )->never();
		Plugin::schedule_purge();
		$this->assertTrue( true );
	}

	public function test_activate_installs_and_schedules() {
		Functions\when( 'wp_generate_password' )->justReturn( 'Token123' );
		Functions\when( 'wp_next_scheduled' )->justReturn( false );
		Functions\expect( 'wp_schedule_single_event' )->once();
		Functions\expect( 'wp_schedule_event' )->once()->with( \Mockery::type( 'int' ), 'daily', Plugin::PURGE_HOOK );
		Functions\expect( 'dbDelta' )->once()->with( \Mockery::pattern( '/CREATE TABLE wp_codo_csp_reports/' ) );

		Plugin::activate();
		$this->assertSame( ReportRepository::DB_VERSION, $this->options[ ReportRepository::DB_OPTION ] );
		$this->assertIsArray( $this->options[ PolicyStore::OPTION ] );
		$this->assertSame( Settings::REPORTING_BUILTIN, $this->options[ Settings::OPTION ]['reporting'] );
	}

	public function test_deactivate_clears_schedules() {
		Functions\expect( 'wp_clear_scheduled_hook' )->once()->with( Plugin::PURGE_HOOK );
		Functions\expect( 'wp_unschedule_hook' )->times( 3 );
		Plugin::deactivate();
		$this->assertTrue( true );
	}

	public function test_network_deactivation_clears_every_site() {
		Functions\when( 'is_multisite' )->justReturn( true );
		$log = array();
		Functions\expect( 'get_sites' )->once()->with(
			array(
				'fields' => 'ids',
				'number' => 0,
			)
		)->andReturn( array( '1', 3 ) );
		Functions\when( 'switch_to_blog' )->alias(
			static function ( $id ) use ( &$log ) {
				$log[] = 'switch ' . var_export( $id, true );
			}
		);
		Functions\when( 'restore_current_blog' )->alias(
			static function () use ( &$log ) {
				$log[] = 'restore';
			}
		);
		Functions\when( 'wp_clear_scheduled_hook' )->alias(
			static function ( $hook ) use ( &$log ) {
				$log[] = 'clear ' . $hook;
			}
		);
		Functions\expect( 'wp_unschedule_hook' )->times( 6 );

		Plugin::deactivate( true );

		$this->assertSame(
			array( 'switch 1', 'clear ' . Plugin::PURGE_HOOK, 'restore', 'switch 3', 'clear ' . Plugin::PURGE_HOOK, 'restore' ),
			$log
		);
	}

	public function test_deactivation_on_one_site_of_a_network_clears_only_that_site() {
		Functions\when( 'is_multisite' )->justReturn( true );
		Functions\expect( 'get_sites' )->never();
		Functions\expect( 'switch_to_blog' )->never();
		Functions\expect( 'wp_clear_scheduled_hook' )->once()->with( Plugin::PURGE_HOOK );
		Functions\expect( 'wp_unschedule_hook' )->times( 3 );
		Plugin::deactivate( false );
		$this->assertTrue( true );
	}

	public function test_network_wide_flag_is_ignored_outside_multisite() {
		Functions\expect( 'get_sites' )->never();
		Functions\expect( 'wp_clear_scheduled_hook' )->once()->with( Plugin::PURGE_HOOK );
		Functions\expect( 'wp_unschedule_hook' )->times( 3 );
		Plugin::deactivate( true );
		$this->assertTrue( true );
	}

	public function test_unschedule() {
		Functions\expect( 'wp_clear_scheduled_hook' )->once()->with( Plugin::PURGE_HOOK );
		Functions\expect( 'wp_unschedule_hook' )->times( 3 );
		Plugin::unschedule();
		$this->assertTrue( true );
	}

	public function test_uninstall_removes_site_data() {
		$this->options       = array(
			Settings::OPTION              => array( 'mode' => 'enforce' ),
			PolicyStore::OPTION           => array(),
			ScanScheduler::URL_OPTION     => array(),
			ReportRepository::DB_OPTION   => '1',
			'unrelated'                   => 'keep',
		);
		$this->transients    = array( RateLimiter::TRANSIENT => 3 );
		$this->wpdb->shouldReceive( 'query' )->once()->with( 'DROP TABLE IF EXISTS wp_codo_csp_reports' );
		Functions\expect( 'delete_post_meta_by_key' )->once()->with( ScanScheduler::META );
		Functions\expect( 'delete_post_meta_by_key' )->once()->with( ScanScheduler::STATUS_META );
		Functions\expect( 'wp_clear_scheduled_hook' )->once()->with( Plugin::PURGE_HOOK );
		Functions\expect( 'wp_unschedule_hook' )->times( 3 );

		Plugin::uninstall();
		$this->assertSame( array( 'unrelated' => 'keep' ), $this->options );
		$this->assertSame( array(), $this->transients );
	}

	public function test_uninstall_network() {
		$this->site_options = array(
			PolicyStore::NETWORK_OPTION => array( 'site' => array() ),
			'other'                     => 1,
		);
		Plugin::uninstall_network();
		$this->assertSame( array( 'other' => 1 ), $this->site_options );
	}
}
