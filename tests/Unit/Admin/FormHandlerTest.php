<?php
/**
 * Tests for FormHandler: capability and nonce checks, scope, every handler.
 *
 * @package CodoDigital\Csp\Tests
 */

namespace CodoDigital\Csp\Tests\Unit\Admin;

use Brain\Monkey\Actions;
use Brain\Monkey\Filters;
use Brain\Monkey\Functions;
use CodoDigital\Csp\Admin\FormHandler;
use CodoDigital\Csp\Settings\PolicyStore;
use CodoDigital\Csp\Settings\Settings;

class FormHandlerTest extends AdminTestCase {

	/**
	 * Times the terminate callable ran.
	 *
	 * @var int
	 */
	private $terminated = 0;

	protected function setUp(): void {
		parent::setUp();
		$this->boot();
	}

	private function handler() {
		return new FormHandler(
			$this->settings,
			$this->store,
			$this->reports,
			$this->scheduler,
			$this->notices,
			function () {
				$this->terminated++;
			}
		);
	}

	/**
	 * Re-boot in enforce mode.
	 *
	 * @return void
	 */
	private function enforce() {
		$this->boot( array( 'mode' => Settings::MODE_ENFORCE ) );
	}

	private function site_redirect( $query ) {
		$this->assertSame( 'https://www.example.com/wp-admin/options-general.php?page=codo-csp&' . $query, $this->redirected_to );
		$this->assertSame( 1, $this->terminated );
	}

	public function test_register_adds_an_admin_post_hook_per_action() {
		$handler = $this->handler();
		$handler->register();
		foreach ( FormHandler::ACTIONS as $action ) {
			$this->assertNotFalse( has_action( 'admin_post_codo_csp_' . $action, array( $handler, 'handle_' . $action ) ), $action );
			$this->assertTrue( method_exists( $handler, 'handle_' . $action ), $action );
		}
	}

	public function test_nonce_action() {
		$this->assertSame( 'codo_csp_scan', FormHandler::nonce_action( 'scan' ) );
	}

	public function test_default_terminator_is_exit_request() {
		$handler = new FormHandler( $this->settings, $this->store, $this->reports, $this->scheduler, $this->notices );
		$ref     = new \ReflectionProperty( FormHandler::class, 'terminate' );
		$ref->setAccessible( true );
		$this->assertSame( array( FormHandler::class, 'exit_request' ), $ref->getValue( $handler ) );
	}

	/**
	 * @return array<string, array{0: string}>
	 */
	public function actions() {
		$out = array();
		foreach ( FormHandler::ACTIONS as $action ) {
			$out[ $action ] = array( $action );
		}
		return $out;
	}

	/**
	 * @dataProvider actions
	 */
	public function test_every_handler_requires_the_capability_before_anything_else( $action ) {
		$this->can = false;
		$before    = $this->options;

		try {
			$this->handler()->{'handle_' . $action}();
			$this->fail( 'wp_die expected' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringContainsString( 'wp_die: You do not have permission', $e->getMessage() );
		}
		$this->assertSame( array(), $this->nonces, 'the nonce is not reached' );
		$this->assertNull( $this->redirected_to );
		$this->assertSame( $before, $this->options );
		$this->assertSame( 0, $this->terminated );
	}

	/**
	 * @dataProvider actions
	 */
	public function test_every_handler_checks_its_own_nonce( $action ) {
		$this->reports->shouldIgnoreMissing();
		$this->scheduler->shouldReceive( 'forget' )->zeroOrMoreTimes();
		$_POST = array(
			'op'        => 'forget',
			'directive' => 'img-src',
			'source'    => 'https://img.example.com',
			'preset'    => 'google-fonts',
		);

		$this->handler()->{'handle_' . $action}();

		$this->assertSame( array( 'codo_csp_' . $action ), $this->nonces );
		$this->assertSame( 1, $this->terminated );
	}

	/**
	 * @dataProvider actions
	 */
	public function test_a_bad_nonce_stops_every_handler( $action ) {
		$this->nonce_valid = false;
		$before            = $this->options;
		$_POST             = array(
			'directive' => 'img-src',
			'source'    => 'https://img.example.com',
			'mode'      => Settings::MODE_ENFORCE,
		);

		try {
			$this->handler()->{'handle_' . $action}();
			$this->fail( 'bad nonce expected' );
		} catch ( \RuntimeException $e ) {
			$this->assertSame( 'bad nonce', $e->getMessage() );
		}
		$this->assertSame( $before, $this->options );
		$this->assertSame( array(), $this->queued() );
		$this->assertNull( $this->redirected_to );
	}

	public function test_network_scope_requires_the_network_capability() {
		$this->can = array( 'manage_options' );
		$_POST     = array(
			'scope'     => 'network',
			'directive' => 'img-src',
			'source'    => 'https://img.example.com',
		);

		$this->expectException( \RuntimeException::class );
		$this->expectExceptionMessage( 'wp_die' );
		$this->handler()->handle_add_rule();
	}

	public function test_site_scope_does_not_accept_the_network_capability_alone() {
		$this->can = array( 'manage_network_options' );
		$_POST     = array(
			'directive' => 'img-src',
			'source'    => 'https://img.example.com',
		);

		$this->expectException( \RuntimeException::class );
		$this->handler()->handle_add_rule();
	}

	public function test_site_capability_is_filterable() {
		Filters\expectApplied( 'codo_csp_capability' )->andReturn( 'edit_csp' );
		$this->can = array( 'edit_csp' );
		$this->reports->shouldReceive( 'clear' )->once();

		$this->handler()->handle_clear_reports();

		$this->assertSame( 'Reports cleared.', $this->notice()['message'] );
	}

	// ----- add_rule -----

	public function test_add_rule_live() {
		$_POST = array(
			'directive' => 'img-src',
			'source'    => ' https://img.example.com/ ',
			'note'      => '<b>Images</b>',
		);

		$this->handler()->handle_add_rule();

		$this->assertSame(
			array(
				'type'    => 'success',
				'message' => 'Allowed https://img.example.com in img-src.',
			),
			$this->notice()
		);
		$rules = $this->store->local( 'site' )->rules();
		$last  = end( $rules );
		$this->assertSame( 'https://img.example.com', $last['s'] );
		$this->assertSame( 'manual', $last['o'] );
		$this->assertSame( 'Images', $last['n'] );
		$this->site_redirect( 'tab=policy' );
	}

	public function test_add_rule_existing_source() {
		$_POST = array(
			'directive' => 'img-src',
			'source'    => 'data:',
		);

		$this->handler()->handle_add_rule();

		$this->assertSame(
			array(
				'type'    => 'info',
				'message' => 'data: is already allowed in img-src.',
			),
			$this->notice()
		);
	}

	public function test_add_rule_that_tightens_goes_to_the_draft() {
		$this->enforce();
		$_POST = array(
			'directive' => 'script-src',
			'source'    => 'sha256-abc123=',
		);

		$this->handler()->handle_add_rule();

		$notice = $this->notice();
		$this->assertSame( 'warning', $notice['type'] );
		$this->assertStringContainsString( "'sha256-abc123=' was added to script-src in the draft", $notice['message'] );
		$this->assertNotNull( $this->store->local_draft( 'site' ) );
		$this->assertFalse( $this->store->local( 'site' )->has( 'script-src', "'sha256-abc123='" ) );
	}

	public function test_add_rule_new_directive_reports_inherited_sources() {
		$_POST = array(
			'directive' => 'media-src',
			'source'    => 'https://media.example.com',
		);

		$this->handler()->handle_add_rule();

		$notices = $this->queued();
		$this->assertCount( 2, $notices );
		$this->assertSame( 'success', $notices[0]['type'] );
		$this->assertSame( 'info', $notices[1]['type'] );
		$this->assertStringContainsString( "media-src was new, so the sources it used to inherit through fallback were copied in ('self')", $notices[1]['message'] );
		$this->assertTrue( $this->store->live( 'site' )->has( 'media-src', "'self'" ) );
	}

	public function test_add_rule_new_directive_in_draft_also_reports_inherited_sources() {
		$this->options[ PolicyStore::OPTION ]['site']['rules'][] = self::rule( 'script-src', "'unsafe-eval'" );
		$this->enforce();
		$_POST = array(
			'directive' => 'script-src-elem',
			'source'    => 'https://js.example.com',
		);

		$this->handler()->handle_add_rule();

		$types = array_column( $this->queued(), 'type' );
		$this->assertContains( 'info', $types );
	}

	/**
	 * @return array<string, array{0: string, 1: string, 2: string}>
	 */
	public function invalid_sources() {
		return array(
			'spaces'            => array( 'img-src', 'two words', 'A source is a single value' ),
			'unknown directive' => array( 'made-up-src', 'https://x.example.com', 'Unknown directive.' ),
			'empty'             => array( 'img-src', '', 'Enter a source.' ),
			'data in scripts'   => array( 'script-src', 'data:', 'would let a script be loaded from anywhere' ),
		);
	}

	/**
	 * @dataProvider invalid_sources
	 */
	public function test_add_rule_invalid_source_is_an_error( $directive, $source, $message ) {
		$_POST  = array(
			'directive' => $directive,
			'source'    => $source,
		);
		$before = $this->options[ PolicyStore::OPTION ];

		$this->handler()->handle_add_rule();

		$notice = $this->notice();
		$this->assertSame( 'error', $notice['type'] );
		$this->assertStringContainsString( $message, $notice['message'] );
		$this->assertSame( $before, $this->options[ PolicyStore::OPTION ] );
		$this->site_redirect( 'tab=policy' );
	}

	public function test_add_rule_source_is_not_run_through_sanitize_text_field() {
		Functions\when( 'sanitize_text_field' )->alias(
			static function ( $text ) {
				return str_replace( "'", '', (string) $text );
			}
		);
		$_POST = array(
			'directive' => 'script-src',
			'source'    => "'unsafe-eval'",
		);

		$this->handler()->handle_add_rule();

		$this->assertTrue( $this->store->live( 'site' )->has( 'script-src', "'unsafe-eval'" ) );
	}

	/**
	 * @return array<string, array{0: string, 1: string, 2: string, 3: string, 4: string}>
	 */
	public function passthrough() {
		return array(
			'scan origin, scan tab'     => array( 'scan', 'scan', 'site', 'scan', 'scan' ),
			'report origin, reports'    => array( 'report', 'reports', 'site', 'report', 'reports' ),
			'forged origin is manual'   => array( 'preset:stripe', 'settings', 'site', 'manual', 'policy' ),
			'unknown return, login tab' => array( 'default', 'evil', 'login', 'manual', 'login' ),
			'bad context is site'       => array( '', '', 'admin', 'manual', 'policy' ),
		);
	}

	/**
	 * @dataProvider passthrough
	 */
	public function test_add_rule_origin_and_return_are_limited( $origin, $return, $context, $stored_origin, $tab ) {
		$_POST = array(
			'directive' => 'img-src',
			'source'    => 'https://img.example.com',
			'origin'    => $origin,
			'return'    => $return,
			'context'   => $context,
		);

		$this->handler()->handle_add_rule();

		$stored_context = 'login' === $context ? 'login' : 'site';
		$rules          = $this->store->local( $stored_context )->rules();
		$last           = end( $rules );
		$this->assertSame( 'https://img.example.com', $last['s'] );
		$this->assertSame( $stored_origin, $last['o'] );
		$this->assertSame( $tab, $this->redirect_args()['tab'] );
	}

	public function test_add_rule_ignores_non_string_fields() {
		$_POST = array(
			'directive' => array( 'img-src' ),
			'source'    => array( 'https://img.example.com' ),
		);

		$this->handler()->handle_add_rule();

		$this->assertSame( 'error', $this->notice()['type'] );
	}

	public function test_add_rule_network() {
		Functions\when( 'is_multisite' )->justReturn( true );
		$this->can = array( 'manage_network_options' );
		$_POST     = array(
			'scope'     => 'network',
			'context'   => 'login',
			'directive' => 'script-src',
			'source'    => 'https://challenges.cloudflare.com/',
			'note'      => 'Turnstile',
			'return'    => 'scan',
		);

		$this->handler()->handle_add_rule();

		$this->assertSame(
			array(
				'type'    => 'success',
				'message' => 'Added https://challenges.cloudflare.com to script-src for every site.',
			),
			$this->notice()
		);
		$this->assertTrue( $this->store->network( 'login' )->has( 'script-src', 'https://challenges.cloudflare.com' ) );
		$this->assertFalse( $this->store->local( 'login' )->has( 'script-src', 'https://challenges.cloudflare.com' ) );
		$this->assertSame( array( 'codo_csp_add_rule' ), $this->nonces );
		$this->assertSame( 'https://www.example.com/wp-admin/network/settings.php?page=codo-csp-network&tab=login', $this->redirected_to );
	}

	public function test_add_rule_network_invalid_source() {
		Functions\when( 'is_multisite' )->justReturn( true );
		$_POST = array(
			'scope'     => 'network',
			'directive' => 'script-src',
			'source'    => '*',
		);

		$this->handler()->handle_add_rule();

		$this->assertSame( 'error', $this->notice()['type'] );
		$this->assertArrayNotHasKey( PolicyStore::NETWORK_OPTION, $this->site_options );
		$this->assertSame( 'site', $this->redirect_args()['tab'] );
	}

	// ----- remove_rule -----

	public function test_remove_rule_live() {
		$_POST = array(
			'directive' => 'script-src',
			'source'    => "'unsafe-inline'",
		);

		$this->handler()->handle_remove_rule();

		$this->assertSame(
			array(
				'type'    => 'success',
				'message' => "Removed 'unsafe-inline' from script-src.",
			),
			$this->notice()
		);
		$this->assertFalse( $this->store->live( 'site' )->has( 'script-src', "'unsafe-inline'" ) );
		$this->site_redirect( 'tab=policy' );
	}

	public function test_remove_rule_draft_when_enforcing() {
		$this->enforce();
		$_POST = array(
			'directive' => 'img-src',
			'source'    => 'data:',
			'context'   => 'login',
		);

		$this->handler()->handle_remove_rule();

		$notice = $this->notice();
		$this->assertSame( 'warning', $notice['type'] );
		$this->assertStringContainsString( 'Removing data: from img-src tightens the enforced policy', $notice['message'] );
		$this->assertTrue( $this->store->local( 'login' )->has( 'img-src', 'data:' ) );
		$this->assertFalse( $this->store->local_draft( 'login' )->has( 'img-src', 'data:' ) );
		$this->site_redirect( 'tab=login' );
	}

	public function test_remove_rule_missing_adds_no_notice() {
		$_POST = array(
			'directive' => 'img-src',
			'source'    => 'https://nowhere.example.com',
		);

		$this->handler()->handle_remove_rule();

		$this->assertSame( array(), $this->queued() );
		$this->site_redirect( 'tab=policy' );
	}

	public function test_remove_rule_network_default_is_an_error_for_a_site() {
		Functions\when( 'is_multisite' )->justReturn( true );
		$this->site_options[ PolicyStore::NETWORK_OPTION ] = array( 'site' => array( self::rule( 'img-src', 'https://cdn.network.test', 'network' ) ) );
		$_POST = array(
			'directive' => 'img-src',
			'source'    => 'https://cdn.network.test',
		);

		$this->handler()->handle_remove_rule();

		$notice = $this->notice();
		$this->assertSame( 'error', $notice['type'] );
		$this->assertStringContainsString( 'network default', $notice['message'] );
		$this->assertTrue( $this->store->network( 'site' )->has( 'img-src', 'https://cdn.network.test' ) );
	}

	public function test_remove_rule_network() {
		Functions\when( 'is_multisite' )->justReturn( true );
		$this->can = array( 'manage_network_options' );
		$this->site_options[ PolicyStore::NETWORK_OPTION ] = array(
			'login' => array(
				self::rule( 'img-src', 'https://cdn.network.test', 'network' ),
				self::rule( 'font-src', 'https://fonts.network.test', 'network' ),
			),
		);
		$_POST = array(
			'scope'     => 'network',
			'context'   => 'login',
			'directive' => 'img-src',
			'source'    => 'https://cdn.network.test',
		);

		$this->handler()->handle_remove_rule();

		$this->assertSame(
			array(
				'type'    => 'success',
				'message' => 'Removed https://cdn.network.test from img-src on every site.',
			),
			$this->notice()
		);
		$this->assertFalse( $this->store->network( 'login' )->has( 'img-src', 'https://cdn.network.test' ) );
		$this->assertTrue( $this->store->network( 'login' )->has( 'font-src', 'https://fonts.network.test' ) );
		$this->assertSame( 'https://www.example.com/wp-admin/network/settings.php?page=codo-csp-network&tab=login', $this->redirected_to );
		$this->assertSame( 1, $this->terminated );
	}

	public function test_remove_rule_network_missing_shows_no_success() {
		Functions\when( 'is_multisite' )->justReturn( true );
		$this->can = array( 'manage_network_options' );
		$_POST     = array(
			'scope'     => 'network',
			'context'   => 'site',
			'directive' => 'img-src',
			'source'    => 'https://gone.network.test',
		);

		$this->handler()->handle_remove_rule();

		$this->assertSame( array(), $this->queued() );
		$this->assertSame( 1, $this->terminated );
	}

	// ----- preset -----

	public function test_preset_unknown() {
		$_POST = array(
			'preset'  => 'nope',
			'context' => 'login',
		);

		$this->handler()->handle_preset();

		$this->assertSame(
			array(
				'type'    => 'error',
				'message' => 'Unknown preset.',
			),
			$this->notice()
		);
		$this->site_redirect( 'tab=login' );
	}

	public function test_preset_unknown_network() {
		$_POST = array(
			'preset' => 'nope',
			'scope'  => 'network',
		);

		$this->handler()->handle_preset();

		$this->assertSame( 'error', $this->notice()['type'] );
		$this->assertSame( 'https://www.example.com/wp-admin/network/settings.php?page=codo-csp-network&tab=site', $this->redirected_to );
	}

	public function test_preset_site() {
		$_POST = array( 'preset' => 'google-fonts' );

		$this->handler()->handle_preset();

		$this->assertSame(
			array(
				'type'    => 'success',
				'message' => 'Google Fonts: 2 sources added.',
			),
			$this->notice()
		);
		$this->assertTrue( $this->store->live( 'site' )->has( 'font-src', 'https://fonts.gstatic.com' ) );
		$this->site_redirect( 'tab=policy' );
	}

	public function test_preset_site_singular() {
		$_POST = array( 'preset' => 'gravatar' );

		$this->handler()->handle_preset();

		// secure.gravatar.com is a default already.
		$this->assertSame( 'Gravatar avatars: 1 source added.', $this->notice()['message'] );
	}

	public function test_preset_network_skips_invalid_sources() {
		Functions\when( 'is_multisite' )->justReturn( true );
		Filters\expectApplied( 'codo_csp_presets' )->andReturnUsing(
			static function ( $presets ) {
				$presets['broken'] = array(
					'label' => 'Broken',
					'rules' => array(
						'script-src' => array( 'data:', 'https://ok.example.com' ),
						'img-src'    => 'https://img.example.com',
					),
				);
				return $presets;
			}
		);
		$_POST = array(
			'preset'  => 'broken',
			'scope'   => 'network',
			'context' => 'login',
		);

		$this->handler()->handle_preset();

		$this->assertSame(
			array(
				'type'    => 'success',
				'message' => 'Broken: 2 sources added.',
			),
			$this->notice()
		);
		$network = $this->store->network( 'login' );
		$this->assertTrue( $network->has( 'script-src', 'https://ok.example.com' ) );
		$this->assertTrue( $network->has( 'img-src', 'https://img.example.com' ) );
		$this->assertFalse( $network->has( 'script-src', 'data:' ) );
		$this->assertSame( 'login', $this->redirect_args()['tab'] );
	}

	// ----- draft -----

	private function make_draft( $context = 'site' ) {
		$this->enforce();
		$this->store->remove( $context, 'img-src', 'data:' );
		$this->assertNotNull( $this->store->local_draft( $context ) );
	}

	public function test_draft_promote() {
		$this->make_draft();
		$_POST = array( 'op' => 'promote' );

		$this->handler()->handle_draft();

		$this->assertSame( 'The draft is now the live policy.', $this->notice()['message'] );
		$this->assertNull( $this->store->local_draft( 'site' ) );
		$this->assertFalse( $this->store->live( 'site' )->has( 'img-src', 'data:' ) );
		$this->site_redirect( 'tab=policy' );
	}

	public function test_draft_discard() {
		$this->make_draft( 'login' );
		$_POST = array(
			'op'      => 'discard',
			'context' => 'login',
		);

		$this->handler()->handle_draft();

		$this->assertSame( 'The draft was discarded.', $this->notice()['message'] );
		$this->assertNull( $this->store->local_draft( 'login' ) );
		$this->assertTrue( $this->store->live( 'login' )->has( 'img-src', 'data:' ) );
		$this->site_redirect( 'tab=login' );
	}

	public function test_draft_without_a_draft_adds_no_notice() {
		foreach ( array( 'promote', 'discard' ) as $op ) {
			$_POST = array( 'op' => $op );
			$this->handler()->handle_draft();
		}
		$this->assertSame( array(), $this->queued() );
		$this->assertSame( 2, $this->terminated );
	}

	public function test_draft_ignores_network_scope_and_uses_the_site_capability() {
		$this->can = array( 'manage_network_options' );
		$_POST     = array( 'scope' => 'network' );

		$this->expectException( \RuntimeException::class );
		$this->handler()->handle_draft();
	}

	// ----- mode -----

	public function test_mode_enforce() {
		Actions\expectDone( 'codo_csp_mode_changed' )->once()->with( true );
		$_POST = array(
			'mode'   => Settings::MODE_ENFORCE,
			'return' => 'scan',
		);

		$this->handler()->handle_mode();

		$this->assertTrue( $this->settings->is_enforcing() );
		$this->assertSame( Settings::MODE_ENFORCE, $this->options[ Settings::OPTION ]['mode'] );
		$notice = $this->notice();
		$this->assertSame( 'success', $notice['type'] );
		$this->assertStringContainsString( 'The policy is now enforced', $notice['message'] );
		$this->site_redirect( 'tab=scan' );
	}

	public function test_mode_report_only_promotes_drafts() {
		$this->make_draft();
		Actions\expectDone( 'codo_csp_mode_changed' )->once()->with( false );
		$_POST = array( 'mode' => Settings::MODE_REPORT_ONLY );

		$this->handler()->handle_mode();

		$this->assertFalse( $this->settings->is_enforcing() );
		$this->assertNull( $this->store->local_draft( 'site' ) );
		$this->assertFalse( $this->store->live( 'site' )->has( 'img-src', 'data:' ) );
		$notices = $this->queued();
		$this->assertCount( 2, $notices );
		$this->assertStringContainsString( 'now Report-Only', $notices[0]['message'] );
		$this->assertSame( 'info', $notices[1]['type'] );
		$this->assertStringContainsString( 'Drafts were made live', $notices[1]['message'] );
		$this->site_redirect( 'tab=policy' );
	}

	public function test_mode_report_only_without_drafts() {
		$this->enforce();
		$_POST = array(
			'mode'   => 'anything',
			'return' => 'Reports!',
		);

		$this->handler()->handle_mode();

		$this->assertFalse( $this->settings->is_enforcing() );
		$this->assertStringContainsString( 'now Report-Only', $this->notice()['message'] );
		$this->site_redirect( 'tab=reports' );
	}

	/**
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_mode_locked_by_constant() {
		define( 'CODO_CSP_MODE', 'report-only' );
		Actions\expectDone( 'codo_csp_mode_changed' )->never();
		$_POST = array(
			'mode'   => Settings::MODE_ENFORCE,
			'return' => 'settings',
		);

		$this->handler()->handle_mode();

		$this->assertSame(
			array(
				'type'    => 'error',
				'message' => 'The mode is set by CODO_CSP_MODE in wp-config.php.',
			),
			$this->notice()
		);
		$this->assertSame( array(), $this->options[ Settings::OPTION ] );
		$this->assertFalse( $this->settings->is_enforcing() );
		$this->site_redirect( 'tab=settings' );
	}

	// ----- settings -----

	public function test_settings_saves_checkboxes_and_reporting() {
		Actions\expectDone( 'codo_csp_policy_changed' )->once()->with( 'site', 'settings' );
		$_POST = array(
			'login_enabled'    => '1',
			'skip_builders'    => '0',
			'upgrade_insecure' => '1',
			'reporting'        => Settings::REPORTING_OFF,
			'external_uri'     => 'not checked when not external',
		);

		$this->handler()->handle_settings();

		$this->assertSame( 'Settings saved.', $this->notice()['message'] );
		$stored = $this->options[ Settings::OPTION ];
		$this->assertTrue( $stored['login_enabled'] );
		$this->assertFalse( $stored['skip_builders'] );
		$this->assertTrue( $stored['upgrade_insecure'] );
		$this->assertFalse( $stored['purge_caches'], 'unchecked boxes are not posted' );
		$this->assertFalse( $stored['scan_on_save'] );
		$this->assertSame( Settings::REPORTING_OFF, $stored['reporting'] );
		$this->assertSame( '', $stored['external_uri'] );
		$this->site_redirect( 'tab=settings' );
	}

	/**
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_settings_keeps_values_fixed_by_constants() {
		define( 'CODO_CSP_LOGIN', false );
		$this->boot( array( 'login_enabled' => true ) );
		$_POST = array(
			'skip_builders' => '1',
			'reporting'     => Settings::REPORTING_OFF,
		);

		$this->handler()->handle_settings();

		$stored = $this->options[ Settings::OPTION ];
		$this->assertTrue( $stored['login_enabled'], 'the stored value survives for when the constant goes' );
		$this->assertTrue( $stored['skip_builders'] );
		$this->assertFalse( $stored['purge_caches'] );
		$this->assertSame( 'Settings saved.', $this->notice()['message'] );
	}

	public function test_settings_external_collector() {
		$_POST = array(
			'reporting'    => Settings::REPORTING_EXTERNAL,
			'external_uri' => 'https://collector.example.com/csp',
		);

		$this->handler()->handle_settings();

		$this->assertSame( 'success', $this->notice()['type'] );
		$this->assertSame( Settings::REPORTING_EXTERNAL, $this->settings->get( 'reporting' ) );
		$this->assertSame( 'https://collector.example.com/csp', $this->settings->get( 'external_uri' ) );
	}

	/**
	 * @return array<string, array{0: string}>
	 */
	public function bad_uris() {
		return array(
			'empty'     => array( '' ),
			'http'      => array( 'http://collector.example.com' ),
			'injection' => array( 'https://x.example.com/;script-src *' ),
			'relative'  => array( '/csp' ),
		);
	}

	/**
	 * @dataProvider bad_uris
	 */
	public function test_settings_external_collector_needs_a_valid_url( $uri ) {
		Actions\expectDone( 'codo_csp_policy_changed' )->never();
		$_POST = array(
			'reporting'     => Settings::REPORTING_EXTERNAL,
			'external_uri'  => $uri,
			'login_enabled' => '0',
		);

		$this->handler()->handle_settings();

		$this->assertSame(
			array(
				'type'    => 'error',
				'message' => 'Enter an https:// URL for the external report collector.',
			),
			$this->notice()
		);
		$this->assertSame( array(), $this->options[ Settings::OPTION ], 'nothing saved' );
		$this->site_redirect( 'tab=settings' );
	}

	public function test_settings_unknown_reporting_choice_is_ignored() {
		$this->boot( array( 'reporting' => Settings::REPORTING_OFF ) );
		$_POST = array( 'reporting' => 'everywhere' );

		$this->handler()->handle_settings();

		$this->assertSame( Settings::REPORTING_OFF, $this->settings->get( 'reporting' ) );
	}

	// ----- reporting -----

	public function test_reporting_start() {
		Actions\expectDone( 'codo_csp_policy_changed' )->once()->with( 'site', 'settings' );
		$_POST = array(
			'op'   => 'start',
			'days' => '30',
		);
		$before = time();

		$this->handler()->handle_reporting();

		$until = (int) $this->settings->get( 'report_until' );
		$this->assertGreaterThanOrEqual( $before + 30 * DAY_IN_SECONDS, $until );
		$this->assertLessThanOrEqual( time() + 30 * DAY_IN_SECONDS, $until );
		$this->assertSame( Settings::REPORTING_BUILTIN, $this->settings->get( 'reporting' ) );
		$this->assertSame( 'Collecting reports until ' . gmdate( 'Y-m-d H:i', $until ) . '.', $this->notice()['message'] );
		$this->site_redirect( 'tab=reports' );
	}

	public function test_reporting_start_with_bad_days_uses_a_week() {
		$_POST = array( 'days' => '-365' );

		$this->handler()->handle_reporting();

		$this->assertEqualsWithDelta( time() + 7 * DAY_IN_SECONDS, (int) $this->settings->get( 'report_until' ), 5 );
	}

	public function test_reporting_stop() {
		$this->boot( array( 'report_until' => time() + 1000 ) );
		$_POST = array( 'op' => 'stop' );

		$this->handler()->handle_reporting();

		$this->assertSame( 0, $this->settings->get( 'report_until' ) );
		$this->assertStringContainsString( 'Report collection stopped.', $this->notice()['message'] );
		$this->site_redirect( 'tab=reports' );
	}

	// ----- clear_reports -----

	public function test_clear_reports() {
		$this->reports->shouldReceive( 'clear' )->once();

		$this->handler()->handle_clear_reports();

		$this->assertSame(
			array(
				'type'    => 'success',
				'message' => 'Reports cleared.',
			),
			$this->notice()
		);
		$this->site_redirect( 'tab=reports' );
	}

	// ----- allow_report -----

	private static function report( array $fields = array() ) {
		return array_merge(
			array(
				'id'          => 7,
				'directive'   => 'img-src',
				'blocked'     => 'https://img.example.com',
				'document'    => 'https://www.example.com/page/',
				'disposition' => 'report',
				'hits'        => 3,
				'last_seen'   => '2026-10-01 10:00:00',
			),
			$fields
		);
	}

	public function test_allow_report_missing_row() {
		$this->reports->shouldReceive( 'find' )->once()->with( 12 )->andReturn( null );
		$_POST = array( 'id' => '-12' );

		$this->handler()->handle_allow_report();

		$this->assertSame(
			array(
				'type'    => 'error',
				'message' => 'That report no longer exists.',
			),
			$this->notice()
		);
		$this->site_redirect( 'tab=reports' );
	}

	public function test_allow_report_without_a_suggestion() {
		$this->reports->shouldReceive( 'find' )->with( 7 )->andReturn( self::report( array( 'directive' => 'made-up' ) ) );
		$_POST = array( 'id' => '7' );

		$this->handler()->handle_allow_report();

		$this->assertSame( 'There is no source to add for this report.', $this->notice()['message'] );
		$this->site_redirect( 'tab=reports' );
	}

	public function test_allow_report_adds_the_source_with_report_origin() {
		$this->reports->shouldReceive( 'find' )->with( 7 )->andReturn(
			self::report(
				array(
					'directive' => 'script-src-elem',
					'blocked'   => 'https://js.example.com',
					'document'  => 'https://www.example.com/',
					'context'   => 'login',
				)
			)
		);
		$_POST = array( 'id' => '7' );

		$this->handler()->handle_allow_report();

		$this->assertSame( 'Allowed https://js.example.com in script-src.', $this->notice()['message'] );
		$rules = $this->store->local( 'login' )->rules();
		$last  = end( $rules );
		$this->assertSame( array( 'script-src', 'https://js.example.com', 'report' ), array( $last['d'], $last['s'], $last['o'] ) );
		$this->assertFalse( $this->store->live( 'site' )->has( 'script-src', 'https://js.example.com' ) );
		$this->site_redirect( 'tab=reports' );
	}

	public function test_allow_report_with_an_unsafe_source_is_an_error() {
		$this->reports->shouldReceive( 'find' )->andReturn(
			self::report(
				array(
					'directive' => 'script-src',
					'blocked'   => 'data:',
				)
			)
		);
		$_POST  = array( 'id' => '7' );
		$before = $this->options[ PolicyStore::OPTION ];

		$this->handler()->handle_allow_report();

		$notice = $this->notice();
		$this->assertSame( 'error', $notice['type'] );
		$this->assertStringContainsString( 'data: in script-src would let a script be loaded from anywhere', $notice['message'] );
		$this->assertSame( $before, $this->options[ PolicyStore::OPTION ] );
		$this->site_redirect( 'tab=reports' );
	}

	// ----- suggest_from_report -----

	/**
	 * @return array<string, array{0: array<string, string>, 1: array<string, string>|null}>
	 */
	public function suggestions() {
		return array(
			'inline'          => array(
				array(
					'directive' => 'style-src-attr',
					'blocked'   => 'inline',
				),
				array(
					'context'   => 'site',
					'directive' => 'style-src',
					'source'    => "'unsafe-inline'",
				),
			),
			'eval'            => array(
				array(
					'directive' => 'script-src',
					'blocked'   => 'eval',
				),
				array(
					'context'   => 'site',
					'directive' => 'script-src',
					'source'    => "'unsafe-eval'",
				),
			),
			'wasm-eval'       => array(
				array(
					'directive' => 'script-src',
					'blocked'   => 'wasm-eval',
				),
				array(
					'context'   => 'site',
					'directive' => 'script-src',
					'source'    => "'wasm-unsafe-eval'",
				),
			),
			'origin'          => array(
				array(
					'directive' => 'frame-src',
					'blocked'   => 'https://www.youtube.com',
				),
				array(
					'context'   => 'site',
					'directive' => 'frame-src',
					'source'    => 'https://www.youtube.com',
				),
			),
			'scheme'          => array(
				array(
					'directive' => 'img-src',
					'blocked'   => 'blob:',
				),
				array(
					'context'   => 'site',
					'directive' => 'img-src',
					'source'    => 'blob:',
				),
			),
			'login context'   => array(
				array(
					'directive' => 'frame-src',
					'blocked'   => 'https://challenges.cloudflare.com',
					'document'  => 'https://www.example.com/custom-login/',
					'context'   => 'login',
				),
				array(
					'context'   => 'login',
					'directive' => 'frame-src',
					'source'    => 'https://challenges.cloudflare.com',
				),
			),
			'login path, site context' => array(
				array(
					'directive' => 'media-src',
					'blocked'   => 'https://m.example.com',
					'document'  => 'https://www.example.com/wp-login.php',
					'context'   => 'site',
				),
				array(
					'context'   => 'site',
					'directive' => 'media-src',
					'source'    => 'https://m.example.com',
				),
			),
			'unknown context' => array(
				array(
					'directive' => 'media-src',
					'blocked'   => 'https://m.example.com',
					'context'   => 'admin',
				),
				array(
					'context'   => 'site',
					'directive' => 'media-src',
					'source'    => 'https://m.example.com',
				),
			),
			'login path, no context' => array(
				array(
					'directive' => 'media-src',
					'blocked'   => 'https://m.example.com',
					'document'  => 'https://www.example.com/wp-login.php',
				),
				array(
					'context'   => 'site',
					'directive' => 'media-src',
					'source'    => 'https://m.example.com',
				),
			),
			'unknown'         => array(
				array(
					'directive' => 'trusted-types',
					'blocked'   => 'https://x.example.com',
				),
				null,
			),
			'junk blocked'    => array(
				array(
					'directive' => 'img-src',
					'blocked'   => '<script>alert(1)</script>',
				),
				null,
			),
			'bare word'       => array(
				array(
					'directive' => 'img-src',
					'blocked'   => 'self',
				),
				null,
			),
			'trusted sink'    => array(
				array(
					'directive' => 'script-src',
					'blocked'   => 'trusted-types-sink',
				),
				null,
			),
		);
	}

	/**
	 * @dataProvider suggestions
	 */
	public function test_suggest_from_report( array $fields, $expected ) {
		$this->assertSame( $expected, FormHandler::suggest_from_report( self::report( $fields ), $this->store ) );
	}

	// ----- scan -----

	public function test_scan_recent() {
		$this->scheduler->shouldReceive( 'queue_recent' )->once()->andReturn( 3 );
		$_POST = array( 'op' => 'recent' );

		$this->handler()->handle_scan();

		$this->assertStringStartsWith( '3 pages queued', $this->notice()['message'] );
		$this->site_redirect( 'tab=scan' );
	}

	public function test_scan_recent_singular() {
		$this->scheduler->shouldReceive( 'queue_recent' )->once()->andReturn( 1 );
		$_POST = array( 'op' => 'recent' );

		$this->handler()->handle_scan();

		$this->assertStringStartsWith( '1 page queued', $this->notice()['message'] );
	}

	public function test_scan_forget() {
		$this->scheduler->shouldReceive( 'forget' )->once()->with( 'https://www.example.com/about/' );
		$this->scheduler->shouldNotReceive( 'scan_url' );
		$_POST = array(
			'op'  => 'forget',
			'url' => 'https://www.example.com/about/',
		);

		$this->handler()->handle_scan();

		$this->assertSame( array(), $this->queued() );
		$this->site_redirect( 'tab=scan' );
	}

	public function test_scan_login_uses_the_login_url() {
		$this->scheduler->shouldReceive( 'scan_url' )->once()->with( 'https://www.example.com/wp-login.php', 'login' )->andReturn(
			array(
				'status'  => 'ok',
				'checked' => 4,
			)
		);
		$_POST = array(
			'op'  => 'login',
			'url' => 'https://elsewhere.example.com/',
		);

		$this->handler()->handle_scan();

		$this->assertSame(
			array(
				'type'    => 'success',
				'message' => 'All 4 resources found are allowed.',
			),
			$this->notice()
		);
	}

	public function test_scan_url_error() {
		$this->scheduler->shouldReceive( 'scan_url' )->once()->with( 'https://www.example.com/broken/', null )->andReturn(
			array(
				'status' => 'error',
				'error'  => 'The page returned HTTP 500.',
			)
		);
		$_POST = array( 'url' => 'https://www.example.com/broken/' );

		$this->handler()->handle_scan();

		$this->assertSame(
			array(
				'type'    => 'error',
				'message' => 'The page returned HTTP 500.',
			),
			$this->notice()
		);
		$this->site_redirect( 'tab=scan' );
	}

	public function test_scan_url_issues() {
		$this->scheduler->shouldReceive( 'scan_url' )->once()->andReturn( array( 'status' => 'issues' ) );
		$_POST = array(
			'op'  => 'url',
			'url' => 'https://www.example.com/',
		);

		$this->handler()->handle_scan();

		$notice = $this->notice();
		$this->assertSame( 'warning', $notice['type'] );
		$this->assertStringContainsString( 'resources the policy does not allow', $notice['message'] );
	}

	public function test_scan_empty_url_defaults_to_home() {
		$this->scheduler->shouldReceive( 'scan_url' )->once()->with( 'https://www.example.com/', null )->andReturn(
			array(
				'status'  => 'ok',
				'checked' => 0,
			)
		);

		$this->handler()->handle_scan();

		$this->assertSame( 'All 0 resources found are allowed.', $this->notice()['message'] );
	}
}
