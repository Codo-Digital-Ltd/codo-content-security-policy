<?php
/**
 * Shared set-up for the admin screen tests.
 *
 * @package CodoDigital\Csp\Tests
 */

namespace CodoDigital\Csp\Tests\Unit\Admin;

use Brain\Monkey\Functions;
use CodoDigital\Csp\Admin\Notices;
use CodoDigital\Csp\Reports\ReportRepository;
use CodoDigital\Csp\Scan\ScanScheduler;
use CodoDigital\Csp\Settings\PolicyStore;
use CodoDigital\Csp\Settings\Settings;
use CodoDigital\Csp\Tests\TestCase;

/**
 * Capability, nonce, redirect and form-helper stubs, plus real Settings,
 * PolicyStore and Notices backed by the in-memory options.
 */
abstract class AdminTestCase extends TestCase {

	/**
	 * True/false for every capability, or the capabilities the user has.
	 *
	 * @var bool|string[]
	 */
	protected $can = true;

	/**
	 * Nonce actions checked, in order.
	 *
	 * @var string[]
	 */
	protected $nonces = array();

	/**
	 * Whether check_admin_referer passes.
	 *
	 * @var bool
	 */
	protected $nonce_valid = true;

	/**
	 * Last redirect target.
	 *
	 * @var string|null
	 */
	protected $redirected_to = null;

	/**
	 * Settings.
	 *
	 * @var Settings
	 */
	protected $settings;

	/**
	 * Policies.
	 *
	 * @var PolicyStore
	 */
	protected $store;

	/**
	 * Notices.
	 *
	 * @var Notices
	 */
	protected $notices;

	/**
	 * Reports.
	 *
	 * @var \Mockery\MockInterface&ReportRepository
	 */
	protected $reports;

	/**
	 * Scans.
	 *
	 * @var \Mockery\MockInterface&ScanScheduler
	 */
	protected $scheduler;

	protected function setUp(): void {
		parent::setUp();
		$_GET  = array();
		$_POST = array();

		Functions\stubs(
			array(
				'current_user_can'    => function ( $capability ) {
					return is_array( $this->can ) ? in_array( $capability, $this->can, true ) : $this->can;
				},
				'wp_die'              => static function ( $message ) {
					throw new \RuntimeException( 'wp_die: ' . $message );
				},
				'check_admin_referer' => function ( $action ) {
					$this->nonces[] = $action;
					if ( ! $this->nonce_valid ) {
						throw new \RuntimeException( 'bad nonce' );
					}
					return 1;
				},
				'wp_safe_redirect'    => function ( $url ) {
					$this->redirected_to = $url;
					return true;
				},
				'wp_nonce_field'      => static function ( $action ) {
					echo '<input type="hidden" name="_wpnonce" value="nonce-' . $action . '">';
				},
				'submit_button'       => static function ( $text = 'Save Changes' ) {
					echo '<button type="submit">' . $text . '</button>';
				},
				'checked'             => static function ( $a, $b = true, $echo = true ) {
					return (string) $a === (string) $b ? ' checked="checked"' : '';
				},
				'wp_login_url'        => 'https://www.example.com/wp-login.php',
			)
		);

		$this->reports   = \Mockery::mock( ReportRepository::class );
		$this->scheduler = \Mockery::mock( ScanScheduler::class );
	}

	protected function tearDown(): void {
		$_GET  = array();
		$_POST = array();
		parent::tearDown();
	}

	/**
	 * Build Settings, a seeded PolicyStore and Notices.
	 *
	 * @param array<string, mixed> $settings Stored settings.
	 * @return void
	 */
	protected function boot( array $settings = array() ) {
		$this->options[ Settings::OPTION ] = $settings;
		$this->settings                    = new Settings();
		$this->store                       = new PolicyStore( $this->settings );
		$this->store->seed();
		$this->notices = new Notices();
	}

	/**
	 * Queued notices for user 1.
	 *
	 * @return array<int, array{type: string, message: string}>
	 */
	protected function queued() {
		return isset( $this->transients['codo_csp_notice_1'] ) ? $this->transients['codo_csp_notice_1'] : array();
	}

	/**
	 * The only queued notice.
	 *
	 * @return array{type: string, message: string}
	 */
	protected function notice() {
		$notices = $this->queued();
		$this->assertCount( 1, $notices, 'exactly one notice: ' . json_encode( $notices ) );
		return $notices[0];
	}

	/**
	 * Query args of the last redirect.
	 *
	 * @return array<string, string>
	 */
	protected function redirect_args() {
		$this->assertNotNull( $this->redirected_to, 'redirected' );
		parse_str( (string) parse_url( $this->redirected_to, PHP_URL_QUERY ), $args );
		return $args;
	}

	/**
	 * A rule in the in-memory format.
	 *
	 * @param string $d Directive.
	 * @param string $s Source.
	 * @param string $o Origin.
	 * @param int    $t Time.
	 * @param string $n Note.
	 * @return array<string, mixed>
	 */
	protected static function rule( $d, $s, $o = 'manual', $t = 0, $n = '' ) {
		return array(
			'd' => $d,
			's' => $s,
			'o' => $o,
			't' => $t,
			'n' => $n,
		);
	}
}
