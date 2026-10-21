<?php
/**
 * Plugin bootstrap.
 *
 * @package CodoDigital\Csp
 */

namespace CodoDigital\Csp;

use CodoDigital\Csp\Admin\AdminPage;
use CodoDigital\Csp\Admin\EditorIntegration;
use CodoDigital\Csp\Admin\FormHandler;
use CodoDigital\Csp\Admin\NetworkPage;
use CodoDigital\Csp\Admin\Notices;
use CodoDigital\Csp\Cache\CachePurger;
use CodoDigital\Csp\Http\HeaderSender;
use CodoDigital\Csp\Reports\RateLimiter;
use CodoDigital\Csp\Reports\ReportEndpoint;
use CodoDigital\Csp\Reports\ReportParser;
use CodoDigital\Csp\Reports\ReportRepository;
use CodoDigital\Csp\Scan\HtmlParser;
use CodoDigital\Csp\Scan\Scanner;
use CodoDigital\Csp\Scan\ScanScheduler;
use CodoDigital\Csp\Settings\PolicyStore;
use CodoDigital\Csp\Settings\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Wires services together and registers hooks.
 */
final class Plugin {

	const PURGE_HOOK     = 'codo_csp_purge_reports';
	const REPORT_MAX_AGE = 30;

	/**
	 * Booted instance.
	 *
	 * @var self|null
	 */
	private static $instance = null;

	/**
	 * Services.
	 *
	 * @var array<string, object>
	 */
	private $services;

	/**
	 * Constructor.
	 *
	 * @param array<string, object> $services Services keyed by name.
	 */
	public function __construct( array $services ) {
		$this->services = $services;
	}

	/**
	 * A service.
	 *
	 * @param string $name Name.
	 * @return object
	 */
	public function get( $name ) {
		return $this->services[ $name ];
	}

	/**
	 * Build the default object graph.
	 *
	 * @return self
	 */
	public static function create() {
		global $wpdb;

		$settings  = new Settings();
		$store     = new PolicyStore( $settings );
		$headers   = new HeaderSender( $settings, $store );
		$reports   = new ReportRepository( $wpdb );
		$scanner   = new Scanner( $store, $headers, new HtmlParser() );
		$scheduler = new ScanScheduler( $settings, $scanner );
		$notices   = new Notices();
		$handler   = new FormHandler( $settings, $store, $reports, $scheduler, $notices );

		return new self(
			array(
				'settings'  => $settings,
				'store'     => $store,
				'headers'   => $headers,
				'reports'   => $reports,
				'endpoint'  => new ReportEndpoint( $settings, new ReportParser(), $reports, new RateLimiter() ),
				'scanner'   => $scanner,
				'scheduler' => $scheduler,
				'purger'    => new CachePurger( $settings ),
				'notices'   => $notices,
				'handler'   => $handler,
				'admin'     => new AdminPage( $settings, $store, $reports, $scheduler, $notices, $headers ),
				'network'   => new NetworkPage( $store, $notices ),
				'editor'    => new EditorIntegration(),
			)
		);
	}

	/**
	 * Boot once, on plugins_loaded.
	 *
	 * @return self
	 */
	public static function boot() {
		if ( null === self::$instance ) {
			self::$instance = self::create();
			self::$instance->register();
		}
		return self::$instance;
	}

	/**
	 * Forget the booted instance (tests).
	 *
	 * @return void
	 */
	public static function reset() {
		self::$instance = null;
	}

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function register() {
		$this->ensure_installed();

		// Reports are answered here, before the theme loads and init runs.
		$this->get( 'endpoint' )->maybe_handle();

		$this->get( 'headers' )->register();
		$this->get( 'scheduler' )->register();
		$this->get( 'purger' )->register();
		add_action( self::PURGE_HOOK, array( $this, 'purge_reports' ) );
		self::schedule_purge();

		if ( is_admin() ) {
			$this->get( 'handler' )->register();
			$this->get( 'admin' )->register();
			$this->get( 'editor' )->register();
			if ( is_multisite() ) {
				$this->get( 'network' )->register();
			}
		}
	}

	/**
	 * Create the table, default policies and settings for this site when
	 * missing (also covers each site of a network-activated install).
	 *
	 * @return bool Whether this was a first install.
	 */
	public function ensure_installed() {
		$this->get( 'reports' )->maybe_install();
		if ( ! $this->get( 'store' )->seed() ) {
			return false;
		}
		// First install: Report-Only, collecting reports for a week.
		$this->get( 'settings' )->collect_for( 7 );
		$this->get( 'settings' )->report_token();
		if ( ! wp_next_scheduled( ScanScheduler::URL_HOOK, array( home_url( '/' ) ) ) ) {
			wp_schedule_single_event( time() + 30, ScanScheduler::URL_HOOK, array( home_url( '/' ) ) );
		}
		return true;
	}

	/**
	 * Daily purge of reports not seen for 30 days.
	 *
	 * @return int Rows deleted.
	 */
	public function purge_reports() {
		return $this->get( 'reports' )->purge_older_than( self::REPORT_MAX_AGE );
	}

	/**
	 * Activation.
	 *
	 * @return void
	 */
	public static function activate() {
		self::create()->ensure_installed();
		self::schedule_purge();
	}

	/**
	 * Schedule the daily purge if missing.
	 *
	 * @return void
	 */
	public static function schedule_purge() {
		if ( ! wp_next_scheduled( self::PURGE_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::PURGE_HOOK );
		}
	}

	/**
	 * Deactivation: stop scheduled work (on every site when network
	 * deactivated). Data stays until uninstall.
	 *
	 * @param bool $network_wide Whether the plugin was network deactivated.
	 * @return void
	 */
	public static function deactivate( $network_wide = false ) {
		if ( $network_wide && is_multisite() ) {
			foreach ( get_sites(
				array(
					'fields' => 'ids',
					'number' => 0,
				)
			) as $site_id ) {
				switch_to_blog( (int) $site_id );
				self::unschedule();
				restore_current_blog();
			}
			return;
		}
		self::unschedule();
	}

	/**
	 * Clear this site's scheduled events.
	 *
	 * @return void
	 */
	public static function unschedule() {
		wp_clear_scheduled_hook( self::PURGE_HOOK );
		ScanScheduler::unschedule();
	}

	/**
	 * Uninstall: remove this site's data.
	 *
	 * @return void
	 */
	public static function uninstall() {
		self::create()->get( 'reports' )->drop();
		delete_option( Settings::OPTION );
		delete_option( PolicyStore::OPTION );
		delete_option( ScanScheduler::URL_OPTION );
		delete_transient( RateLimiter::TRANSIENT );
		delete_post_meta_by_key( ScanScheduler::META );
		delete_post_meta_by_key( ScanScheduler::STATUS_META );
		self::unschedule();
	}

	/**
	 * Uninstall: remove network data (multisite).
	 *
	 * @return void
	 */
	public static function uninstall_network() {
		delete_site_option( PolicyStore::NETWORK_OPTION );
	}
}
