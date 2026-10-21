<?php
/**
 * Tests for AdminPage: hooks, menu, assets, every tab and the status bar.
 *
 * @package CodoDigital\Csp\Tests
 */

namespace CodoDigital\Csp\Tests\Unit\Admin;

use Brain\Monkey\Functions;
use CodoDigital\Csp\Admin\AdminPage;
use CodoDigital\Csp\Http\HeaderSender;
use CodoDigital\Csp\Settings\PolicyStore;
use CodoDigital\Csp\Settings\Settings;

class AdminPageTest extends AdminTestCase {

	/**
	 * Headers.
	 *
	 * @var \Mockery\MockInterface&HeaderSender
	 */
	private $headers;

	protected function setUp(): void {
		parent::setUp();
		$this->boot();
		$this->headers = \Mockery::mock( HeaderSender::class );
		$this->headers->shouldReceive( 'build' )->andReturn( array( 'Content-Security-Policy-Report-Only' => array( "default-src 'self'" ) ) )->byDefault();
		$this->scheduler->shouldReceive( 'url_scans' )->andReturn( array() )->byDefault();
		$this->scheduler->shouldReceive( 'flagged_posts' )->andReturn( array() )->byDefault();
		$this->reports->shouldReceive( 'count' )->andReturn( 0 )->byDefault();
		$this->reports->shouldReceive( 'dropped' )->andReturn( 0 )->byDefault();
	}

	private function page() {
		return new AdminPage( $this->settings, $this->store, $this->reports, $this->scheduler, $this->notices, $this->headers );
	}

	private function render( $tab = null, array $settings = null ) {
		if ( null !== $settings ) {
			$this->boot( $settings );
		}
		if ( null !== $tab ) {
			$_GET['tab'] = $tab;
		}
		ob_start();
		$this->page()->render();
		return ob_get_clean();
	}

	// ----- hooks, menu, assets -----

	public function test_register() {
		$page = $this->page();
		$page->register();
		$this->assertNotFalse( has_action( 'admin_menu', array( $page, 'add_menu' ) ) );
		$this->assertNotFalse( has_action( 'admin_enqueue_scripts', array( $page, 'enqueue' ) ) );
		$this->assertNotFalse( has_filter( 'plugin_action_links_codo-content-security-policy/codo-content-security-policy.php', array( $page, 'action_links' ) ) );
	}

	public function test_add_menu() {
		$page = $this->page();
		Functions\expect( 'add_options_page' )->once()->with( 'Content Security Policy', 'Content Security Policy', 'manage_options', 'codo-csp', array( $page, 'render' ) );
		$page->add_menu();
	}

	public function test_action_links_prepend_settings() {
		$links = $this->page()->action_links( array( 'deactivate' => '<a>Deactivate</a>' ) );
		$this->assertSame( '<a href="https://www.example.com/wp-admin/options-general.php?page=codo-csp&tab=policy">Settings</a>', $links[0] );
		$this->assertSame( '<a>Deactivate</a>', $links['deactivate'] );
		$this->assertCount( 2, $links );
	}

	public function test_enqueue_only_on_its_screens() {
		Functions\expect( 'wp_register_style' )->twice()->with( 'codo-csp-admin', false, array(), CODO_CSP_VERSION );
		Functions\expect( 'wp_enqueue_style' )->twice()->with( 'codo-csp-admin' );
		Functions\expect( 'wp_add_inline_style' )->twice()->with( 'codo-csp-admin', AdminPage::css() );

		$page = $this->page();
		$page->enqueue( 'index.php' );
		$page->enqueue( 'settings_page_codo-mailer' );
		$page->enqueue( 'settings_page_codo-csp' );
		$page->enqueue( 'settings_page_codo-csp-network' );
	}

	public function test_css() {
		$css = AdminPage::css();
		$this->assertStringContainsString( '.codo-csp-inline{display:inline}', $css );
		$this->assertStringContainsString( '.codo-csp-status.is-disabled', $css );
		$this->assertStringNotContainsString( '<', $css );
	}

	public function test_url() {
		$page = $this->page();
		$this->assertSame( 'https://www.example.com/wp-admin/options-general.php?page=codo-csp&tab=policy', $page->url() );
		$this->assertSame( 'https://www.example.com/wp-admin/options-general.php?page=codo-csp&tab=reports&paged=3', $page->url( 'reports', array( 'paged' => 3 ) ) );
	}

	public function test_tabs_with_login() {
		$this->assertSame(
			array(
				'policy'   => 'Policy',
				'login'    => 'Login page',
				'reports'  => 'Reports',
				'scan'     => 'Scan',
				'settings' => 'Settings',
			),
			$this->page()->tabs()
		);
	}

	public function test_tabs_without_login() {
		$this->boot( array( 'login_enabled' => false ) );
		$this->assertSame( array( 'policy', 'reports', 'scan', 'settings' ), array_keys( $this->page()->tabs() ) );
	}

	// ----- render: frame and status -----

	public function test_render_requires_the_capability() {
		$this->can = array( 'manage_network_options' );
		$this->expectException( \RuntimeException::class );
		$this->expectExceptionMessage( 'wp_die: You do not have permission to view this page.' );
		$this->page()->render();
	}

	public function test_render_without_capability_prints_nothing() {
		$this->can = false;
		ob_start();
		try {
			$this->page()->render();
		} catch ( \RuntimeException $e ) {
			$this->assertStringStartsWith( 'wp_die', $e->getMessage() );
		}
		$this->assertSame( '', ob_get_clean() );
	}

	public function test_render_policy_tab_by_default_in_report_only() {
		$this->notices->add( 'warning', 'Queued <notice>' );

		$html = $this->render( null, array( 'report_until' => 1893456000 ) );

		$this->assertStringStartsWith( '<div class="wrap codo-csp"><h1>Content Security Policy</h1>', $html );
		$this->assertStringContainsString( '<div class="notice notice-warning is-dismissible"><p>Queued &lt;notice&gt;</p></div>', $html );
		$this->assertStringContainsString( '<div class="codo-csp-status is-report-only"><div><strong>Report-Only</strong> &mdash; nothing is blocked.', $html );
		$this->assertStringContainsString( 'name="mode" value="enforce"><input type="hidden" name="return" value="policy">', $html );
		$this->assertStringContainsString( '<button type="submit" class="button button-primary">Enforce the policy</button>', $html );
		$this->assertStringContainsString( '<div class="description">Collecting reports until 2030-01-01 00:00.</div>', $html );
		$this->assertStringContainsString( '<nav class="nav-tab-wrapper" aria-label="Sections">', $html );
		$this->assertStringContainsString( 'tab=policy" class="nav-tab nav-tab-active" aria-current="page">Policy</a>', $html );
		$this->assertStringContainsString( 'tab=login" class="nav-tab">Login page</a>', $html );
		$this->assertStringContainsString( 'Sent on every front-end page', $html );
		$this->assertStringNotContainsString( 'Network defaults are set by the network administrator', $html );
		$this->assertStringContainsString( 'name="context" value="site"', $html );
		$this->assertStringContainsString( '<h2>Headers sent</h2>', $html );
		$this->assertStringContainsString( '<p><strong>Content-Security-Policy-Report-Only</strong><code class="codo-csp-header">default-src &#039;self&#039;</code></p>', $html );
		$this->assertStringContainsString( 'Total size: ' . ( strlen( 'Content-Security-Policy-Report-Only' ) + strlen( "default-src 'self'" ) + 4 ) . ' B.', $html );
		$this->assertStringNotContainsString( 'over 4 KB', $html );
		$this->assertStringEndsWith( '</div>', $html );
		$this->assertArrayNotHasKey( 'codo_csp_notice_1', $this->transients, 'notices are shown once' );
	}

	public function test_render_unknown_tab_is_policy() {
		$html = $this->render( 'bogus' );
		$this->assertStringContainsString( 'tab=policy" class="nav-tab nav-tab-active"', $html );
		$this->assertStringContainsString( 'Sent on every front-end page', $html );
	}

	public function test_render_login_tab_falls_back_to_policy_when_login_is_off() {
		$html = $this->render( 'login', array( 'login_enabled' => false ) );
		$this->assertStringNotContainsString( 'tab=login', $html );
		$this->assertStringContainsString( 'Sent on every front-end page', $html );
	}

	public function test_render_login_tab_on_multisite() {
		Functions\when( 'is_multisite' )->justReturn( true );
		$this->headers->shouldReceive( 'build' )->once()->with( 'login' )->andReturn( array() );

		$html = $this->render( 'Login' );

		$this->assertStringContainsString( 'tab=login" class="nav-tab nav-tab-active" aria-current="page">Login page', $html );
		$this->assertStringContainsString( 'wp-login.php has its own policy', $html );
		$this->assertStringContainsString( 'Network defaults are set by the network administrator and apply to every site.', $html );
		$this->assertStringContainsString( 'name="context" value="login"', $html );
		$this->assertStringContainsString( '<h2>Headers sent</h2><p>None.</p>', $html );
	}

	public function test_status_enforced_and_not_collecting() {
		$html = $this->render( 'scan', array( 'mode' => Settings::MODE_ENFORCE ) );

		$this->assertStringContainsString( '<div class="codo-csp-status is-enforced"><div><strong>Enforced</strong> &mdash; browsers block anything', $html );
		$this->assertStringContainsString( 'name="mode" value="report-only"><input type="hidden" name="return" value="scan">', $html );
		$this->assertStringContainsString( '<button type="submit" class="button">Switch to Report-Only</button>', $html );
		$this->assertStringContainsString( '<div class="description">Not collecting reports.</div>', $html );
	}

	public function test_status_external_reporting() {
		$html = $this->render(
			'settings',
			array(
				'reporting'    => Settings::REPORTING_EXTERNAL,
				'external_uri' => 'https://collector.example.com/r?a=1&b=<2>',
			)
		);
		$this->assertStringContainsString( '<div class="description">Reports go to https://collector.example.com/r?a=1&amp;b=&lt;2&gt;.</div>', $html );
	}

	public function test_header_preview_warns_over_4kb() {
		$this->headers->shouldReceive( 'build' )->with( 'site' )->andReturn(
			array(
				'Content-Security-Policy'             => array( str_repeat( 'a', 3000 ) ),
				'Content-Security-Policy-Report-Only' => array( str_repeat( 'b', 1000 ), '<x>' ),
			)
		);

		$html = $this->render();

		$size = strlen( 'Content-Security-Policy' ) + 3000 + 4 + 2 * ( strlen( 'Content-Security-Policy-Report-Only' ) + 4 ) + 1000 + 3;
		$this->assertGreaterThan( 4096, $size );
		$this->assertStringContainsString( 'Total size: ' . $size . ' B.', $html );
		$this->assertStringContainsString( '<code class="codo-csp-header">&lt;x&gt;</code>', $html );
		$this->assertStringContainsString( '<div class="notice notice-warning inline"><p>The headers are over 4 KB.', $html );
	}

	/**
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_status_disabled_by_constant() {
		define( 'CODO_CSP_DISABLE', true );

		$html = $this->render();

		$this->assertStringContainsString( '<div class="codo-csp-status is-disabled"><strong>Disabled by CODO_CSP_DISABLE in wp-config.php: no policy headers are sent.</strong></div>', $html );
		$this->assertStringNotContainsString( 'Enforce the policy', $html );
		$this->assertStringNotContainsString( 'codo_csp_mode', $html );
		$this->assertStringContainsString( 'nav-tab-wrapper', $html );
	}

	/**
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_status_mode_locked_by_constant() {
		define( 'CODO_CSP_MODE', 'enforce' );

		$html = $this->render();

		$this->assertStringContainsString( '<strong>Enforced</strong>', $html );
		$this->assertStringContainsString( '<span class="description">Set by CODO_CSP_MODE in wp-config.php.</span>', $html );
		$this->assertStringNotContainsString( 'Switch to Report-Only', $html );
		$this->assertStringNotContainsString( 'codo_csp_mode', $html );
	}

	// ----- reports tab -----

	public function test_reports_tab_external() {
		$html = $this->render(
			'reports',
			array(
				'reporting'    => Settings::REPORTING_EXTERNAL,
				'external_uri' => 'https://collector.example.com/csp',
			)
		);

		$this->assertStringContainsString( '<p>Reports are sent to https://collector.example.com/csp, so none are collected here.</p>', $html );
		$this->assertStringNotContainsString( 'Collect for', $html );
		$this->assertStringNotContainsString( 'Stop collecting', $html );
		$this->assertStringContainsString( '<p><em>No reports.</em></p>', $html );
		$this->assertStringNotContainsString( 'Clear all reports', $html );
	}

	public function test_reports_tab_not_collecting_offers_windows() {
		$this->reports->shouldNotReceive( 'page' );

		$html = $this->render( 'reports', array( 'report_until' => 0 ) );

		$this->assertStringContainsString( 'name="op" value="start"><input type="hidden" name="days" value="1"><input type="hidden" name="_wpnonce" value="nonce-codo_csp_reporting"><button type="submit" class="button">Collect for 1 day</button>', $html );
		$this->assertStringContainsString( '>Collect for 7 days</button>', $html );
		$this->assertStringContainsString( '>Collect for 30 days</button>', $html );
		$this->assertStringNotContainsString( 'Stop collecting', $html );
		$this->assertStringContainsString( '<p><em>No reports.</em></p>', $html );
	}

	public function test_reports_tab_collecting_offers_stop() {
		$html = $this->render( 'reports', array( 'report_until' => 1893456000 ) );

		$this->assertStringContainsString( '<p>Collecting reports until 2030-01-01 00:00. <form', $html );
		$this->assertStringContainsString( 'name="op" value="stop"', $html );
		$this->assertStringContainsString( '>Stop collecting</button>', $html );
		$this->assertStringNotContainsString( 'Collect for', $html );
	}

	private static function report( $id, array $fields ) {
		return array_merge(
			array(
				'id'          => $id,
				'directive'   => 'img-src',
				'blocked'     => 'https://img.example.com',
				'document'    => 'https://www.example.com/',
				'disposition' => 'report',
				'hits'        => 1,
				'last_seen'   => '2026-10-01 10:00:00',
			),
			$fields
		);
	}

	/**
	 * The <tr> of a report row (by its blocked value).
	 *
	 * @param string $html    HTML.
	 * @param string $blocked Escaped blocked value.
	 * @param string $directive Directive.
	 * @return string
	 */
	private static function report_row( $html, $directive, $blocked ) {
		$found = preg_match( '~<tr><td><code>' . preg_quote( $directive, '~' ) . '</code>(?: <span class="codo-csp-badge">login page</span>)?</td><td><code>' . preg_quote( $blocked, '~' ) . '</code>(?:(?!</tr>).)*</tr>~s', $html, $m );
		return $found ? $m[0] : '';
	}

	/**
	 * A scan result.
	 *
	 * @param array<string, mixed> $fields Fields.
	 * @return array<string, mixed>
	 */
	private static function scan( array $fields = array() ) {
		return array_merge(
			array(
				'url'      => 'https://www.example.com/',
				'context'  => 'site',
				'status'   => 'ok',
				'time'     => 1767225600,
				'error'    => '',
				'warnings' => array(),
				'checked'  => 5,
				'issues'   => array(),
				'draft'    => array(),
			),
			$fields
		);
	}

	private static function issue( array $fields ) {
		return array_merge(
			array(
				'directive' => 'img-src',
				'target'    => 'img-src',
				'source'    => 'https://img.example.com',
				'inline'    => false,
				'count'     => 1,
				'example'   => 'https://img.example.com/a.png',
			),
			$fields
		);
	}

	public function test_reports_tab_rows_in_report_only() {
		$this->reports->shouldReceive( 'count' )->andReturn( 8 );
		$this->reports->shouldReceive( 'page' )->once()->with( 1, 25 )->andReturn(
			array(
				self::report(
					1,
					array(
						'blocked'     => 'https://img.cdn.test',
						'disposition' => 'enforce',
						'hits'        => 1234,
					)
				),
				self::report(
					2,
					array(
						'directive' => 'script-src',
						'blocked'   => 'eval',
					)
				),
				self::report( 3, array( 'blocked' => 'data:' ) ),
				self::report(
					4,
					array(
						'directive' => 'script-src-elem',
						'blocked'   => 'inline',
					)
				),
				self::report(
					5,
					array(
						'directive' => 'made-up',
						'blocked'   => 'https://x.example.com',
					)
				),
				self::report(
					6,
					array(
						'directive' => 'script-src',
						'blocked'   => 'wasm-eval',
					)
				),
				self::report( 7, array( 'blocked' => 'https://www.example.com' ) ),
				self::report(
					8,
					array(
						'directive' => 'frame-src',
						'blocked'   => 'https://challenges.cloudflare.com',
						'document'  => 'https://www.example.com/wp-login.php',
						'context'   => 'login',
					)
				),
			)
		);
		$this->scheduler->shouldReceive( 'url_scans' )->andReturn(
			array( 'https://www.example.com/' => self::scan( array( 'issues' => array( self::issue( array( 'source' => 'https://img.cdn.test' ) ) ) ) ) )
		);
		$this->scheduler->shouldReceive( 'flagged_posts' )->andReturn(
			array(
				array(
					'id'     => 9,
					'title'  => 'Post',
					'result' => self::scan(
						array(
							'status' => 'issues',
							'draft'  => array( self::issue( array( 'target' => 'frame-src', 'source' => 'https://challenges.cloudflare.com' ) ) ),
						)
					),
				),
			)
		);

		$html = $this->render( 'reports', array( 'report_until' => 0 ) );

		$this->assertStringContainsString( '<table class="widefat striped"><thead><tr><th scope="col">Directive</th><th scope="col">Blocked</th>', $html );

		$blocked = self::report_row( $html, 'img-src', 'https://img.cdn.test' );
		$this->assertStringContainsString( '<span class="codo-csp-badge">also found by a scan</span>', $blocked );
		$this->assertStringContainsString( '<td>1234</td>', $blocked );
		$this->assertStringContainsString( '<td>2026-10-01 10:00</td>', $blocked );
		$this->assertStringContainsString( '<td>Blocked</td>', $blocked );
		$this->assertStringContainsString( 'name="action" value="codo_csp_allow_report"', $blocked );
		$this->assertStringContainsString( 'name="id" value="1"', $blocked );
		$this->assertStringContainsString( '>Allow https://img.cdn.test in img-src</button>', $blocked );
		$this->assertStringNotContainsString( 'This weakens the policy', $blocked );

		$eval = self::report_row( $html, 'script-src', 'eval' );
		$this->assertStringContainsString( '<td>Would be blocked</td>', $eval );
		$this->assertStringContainsString( '>Allow &#039;unsafe-eval&#039; in script-src</button>', $eval );
		$this->assertStringContainsString( 'This weakens the policy. Prefer fixing the code that needs it.', $eval );
		$this->assertStringNotContainsString( 'also found by a scan', $eval );

		foreach ( array( array( 'img-src', 'data:' ), array( 'script-src-elem', 'inline' ), array( 'img-src', 'https://www.example.com' ) ) as $allowed ) {
			$row = self::report_row( $html, $allowed[0], $allowed[1] );
			$this->assertStringContainsString( '<td>Allowed now</td><td></td></tr>', $row, $allowed[1] );
		}

		$unknown = self::report_row( $html, 'made-up', 'https://x.example.com' );
		$this->assertStringContainsString( '<td>Would be blocked</td><td></td></tr>', $unknown );

		$wasm = self::report_row( $html, 'script-src', 'wasm-eval' );
		$this->assertStringContainsString( '>Allow &#039;wasm-unsafe-eval&#039; in script-src</button>', $wasm );
		$this->assertStringNotContainsString( 'This weakens the policy', $wasm );

		$login = self::report_row( $html, 'frame-src', 'https://challenges.cloudflare.com' );
		$this->assertStringContainsString( 'name="context" value="login"', $login );
		$this->assertStringContainsString( 'also found by a scan', $login );
		$this->assertStringContainsString( '<td>https://www.example.com/wp-login.php</td>', $login );
		$this->assertStringContainsString( '<code>frame-src</code> <span class="codo-csp-badge">login page</span></td>', $login );
		$this->assertSame( 1, substr_count( $html, '>login page</span>' ), 'only login-context rows are badged' );
		$this->assertStringContainsString( '<th scope="col">Latest page</th>', $html );
		$this->assertStringNotContainsString( 'The report table is full', $html );

		$this->assertStringNotContainsString( 'tablenav-pages', $html );
		$this->assertStringContainsString( 'value="nonce-codo_csp_clear_reports"><button type="submit" class="button">Clear all reports</button>', $html );
	}

	public function test_reports_tab_when_enforcing() {
		$this->options[ PolicyStore::OPTION ]['site']['rules'][] = self::rule( 'script-src', "'unsafe-eval'" );
		$this->options[ PolicyStore::OPTION ]['site']['draft']   = array(
			'rules' => $this->options[ PolicyStore::OPTION ]['site']['rules'],
			't'     => 1767225600,
		);
		$this->reports->shouldReceive( 'count' )->andReturn( 5 );
		$this->reports->shouldReceive( 'page' )->andReturn(
			array(
				self::report(
					5,
					array(
						'blocked' => 'https://img.login.test',
						'context' => 'login',
					)
				),
				self::report(
					4,
					array(
						'directive' => 'script-src',
						'blocked'   => 'wasm-eval',
					)
				),
				self::report( 1, array( 'blocked' => 'https://img.draft.test' ) ),
				self::report(
					2,
					array(
						'directive'   => 'img-src',
						'blocked'     => 'https://img.live.test',
						'disposition' => 'enforce',
					)
				),
				self::report(
					3,
					array(
						'directive' => 'script-src',
						'blocked'   => 'eval',
						'document'  => '<script>x</script>',
					)
				),
			)
		);

		$html = $this->render( 'reports', array( 'mode' => Settings::MODE_ENFORCE ) );

		$this->assertStringContainsString( '<td>Would be blocked by the draft</td>', self::report_row( $html, 'img-src', 'https://img.draft.test' ) );
		$login = self::report_row( $html, 'img-src', 'https://img.login.test' );
		$this->assertStringContainsString( '<code>img-src</code> <span class="codo-csp-badge">login page</span></td>', $login );
		$this->assertStringContainsString( '<td>Reported while in Report-Only</td>', $login, 'the login context has no draft' );
		$this->assertStringContainsString( 'name="context" value="login"', $login );
		$this->assertStringContainsString( '<td>Blocked</td>', self::report_row( $html, 'img-src', 'https://img.live.test' ) );
		$eval = self::report_row( $html, 'script-src', 'eval' );
		$this->assertStringContainsString( '<td>Allowed now</td>', $eval );
		$this->assertStringContainsString( '<td>&lt;script&gt;x&lt;/script&gt;</td>', $eval );
		$this->assertStringNotContainsString( '<script>', $html );
		$this->assertStringContainsString( '<td>Allowed now</td><td></td></tr>', self::report_row( $html, 'script-src', 'wasm-eval' ), "'unsafe-eval' also allows WebAssembly" );
	}

	public function test_reports_tab_wasm_allowed_by_wasm_unsafe_eval() {
		$this->options[ PolicyStore::OPTION ]['site']['rules'][] = self::rule( 'script-src', "'wasm-unsafe-eval'" );
		$this->options[ PolicyStore::OPTION ]['login']['rules']  = array();
		$this->reports->shouldReceive( 'count' )->andReturn( 4 );
		$this->reports->shouldReceive( 'page' )->andReturn(
			array(
				self::report( 4, array( 'blocked' => 'mediastream:' ) ),
				self::report(
					1,
					array(
						'directive' => 'script-src',
						'blocked'   => 'wasm-eval',
					)
				),
				self::report(
					2,
					array(
						'directive' => 'script-src',
						'blocked'   => 'eval',
					)
				),
				self::report(
					3,
					array(
						'directive' => 'worker-src',
						'blocked'   => 'wasm-eval',
						'document'  => 'https://www.example.com/wp-login.php',
						'context'   => 'login',
					)
				),
			)
		);

		$html = $this->render( 'reports' );

		$this->assertStringContainsString( '<td>Allowed now</td><td></td></tr>', self::report_row( $html, 'script-src', 'wasm-eval' ) );
		$this->assertStringContainsString( '>Allow &#039;unsafe-eval&#039; in script-src</button>', self::report_row( $html, 'script-src', 'eval' ) );
		$this->assertStringContainsString( '<td>Allowed now</td><td></td></tr>', self::report_row( $html, 'worker-src', 'wasm-eval' ), 'no policy at all allows everything' );
		$this->assertStringContainsString( '>Allow mediastream: in img-src</button>', self::report_row( $html, 'img-src', 'mediastream:' ) );
	}

	public function test_reports_tab_warns_when_reports_were_dropped() {
		$this->reports->shouldReceive( 'dropped' )->andReturn( 1 );
		$html = $this->render( 'reports' );
		$this->assertStringContainsString( '<div class="notice notice-error inline"><p><strong>The report table is full: 1 report about a new violation was dropped.</strong> Until you clear the reports, a quiet Reports tab does not mean nothing is blocked.', $html );
		$this->assertStringContainsString( '<p><em>No reports.</em></p>', $html );
	}

	public function test_reports_tab_dropped_count_plural() {
		$this->reports->shouldReceive( 'dropped' )->andReturn( 12 );
		$html = $this->render( 'reports' );
		$this->assertStringContainsString( 'The report table is full: 12 reports about new violations were dropped.', $html );
	}

	public function test_reports_tab_pagination() {
		$_GET['paged'] = '2';
		$this->reports->shouldReceive( 'count' )->andReturn( 60 );
		$this->reports->shouldReceive( 'page' )->once()->with( 2, 25 )->andReturn( array( self::report( 30, array() ) ) );

		$html = $this->render( 'reports' );

		$this->assertStringContainsString(
			'<p class="tablenav-pages"><a href="https://www.example.com/wp-admin/options-general.php?page=codo-csp&tab=reports&paged=1">1</a> <strong>2</strong> <a href="https://www.example.com/wp-admin/options-general.php?page=codo-csp&tab=reports&paged=3">3</a> </p>',
			$html
		);
	}

	public function test_reports_tab_page_number_is_a_positive_integer() {
		$_GET['paged'] = '-4';
		$this->reports->shouldReceive( 'count' )->andReturn( 1 );
		$this->reports->shouldReceive( 'page' )->once()->with( 4, 25 )->andReturn( array() );

		$this->render( 'reports' );

		$_GET['paged'] = '0';
		$this->reports->shouldReceive( 'page' )->once()->with( 1, 25 )->andReturn( array() );
		$this->render( 'reports' );
	}

	// ----- scan tab -----

	public function test_scan_tab_forms_without_results() {
		$html = $this->render( 'scan' );

		$this->assertStringContainsString( '<input type="hidden" name="action" value="codo_csp_scan"><input type="hidden" name="context" value="site"><input type="hidden" name="scope" value="site"><input type="hidden" name="op" value="url">', $html );
		$this->assertStringContainsString( '<input type="url" class="regular-text code" id="codo-csp-scan-url" name="url" value="https://www.example.com/" required> <button type="submit">Scan now</button>', $html );
		$this->assertStringContainsString( 'name="op" value="login"', $html );
		$this->assertStringContainsString( '>Scan the login page</button>', $html );
		$this->assertStringContainsString( 'name="op" value="recent"', $html );
		$this->assertStringContainsString( '>Scan the 20 most recently updated pages</button>', $html );
		$this->assertStringNotContainsString( 'Recent scans', $html );
		$this->assertStringContainsString( '<h2>Published content with problems</h2><p><em>None found by the latest scans.</em></p>', $html );
	}

	public function test_scan_tab_without_login() {
		$html = $this->render( 'scan', array( 'login_enabled' => false ) );
		$this->assertStringNotContainsString( 'Scan the login page', $html );
		$this->assertStringContainsString( 'Scan the 20 most recently updated pages', $html );
	}

	public function test_scan_tab_with_results() {
		$this->scheduler->shouldReceive( 'url_scans' )->andReturn(
			array(
				'https://www.example.com/'             => self::scan(),
				'https://www.example.com/wp-login.php' => self::scan(
					array(
						'url'      => 'https://www.example.com/wp-login.php',
						'context'  => 'login',
						'status'   => 'issues',
						'warnings' => array( 'The page sets its own <meta> policy.' ),
						'issues'   => array(
							self::issue(
								array(
									'directive' => 'script-src-elem',
									'target'    => 'script-src',
									'source'    => 'https://challenges.cloudflare.com',
									'count'     => 2,
									'example'   => 'https://challenges.cloudflare.com/turnstile/v0/api.js',
								)
							),
							self::issue(
								array(
									'directive' => 'style-src-attr',
									'target'    => 'style-src',
									'source'    => "'unsafe-inline'",
									'inline'    => true,
									'count'     => 3,
								)
							),
							self::issue(
								array(
									'directive' => 'img-src',
									'source'    => 'data:',
									'count'     => 1500,
								)
							),
						),
					)
				),
			)
		);
		$this->scheduler->shouldReceive( 'flagged_posts' )->andReturn(
			array(
				array(
					'id'     => 3,
					'title'  => 'Hello <world>',
					'result' => self::scan(
						array(
							'url'    => 'https://www.example.com/hello/',
							'status' => 'issues',
							'draft'  => array(
								self::issue(
									array(
										'directive' => 'style-src-elem',
										'target'    => 'style-src',
										'source'    => "'unsafe-inline'",
										'inline'    => true,
										'count'     => 1,
									)
								),
							),
						)
					),
				),
				array(
					'id'     => 4,
					'title'  => '',
					'result' => self::scan(
						array(
							'url'    => 'https://www.example.com/broken/',
							'status' => 'error',
							'error'  => 'HTTP 500 <oops>',
						)
					),
				),
			)
		);

		$html = $this->render( 'scan' );

		$this->assertStringContainsString( '<h2>Recent scans</h2><details class="codo-csp-scan"><summary><span class="codo-csp-ok">&#10003;</span> <strong>https://www.example.com/</strong> <span class="description">2026-01-01 00:00</span></summary>', $html );
		$this->assertStringContainsString( '<p>All 5 resources found are allowed.</p>', $html );
		$this->assertStringContainsString( '<details class="codo-csp-scan" open><summary><span class="codo-csp-bad">&#9888;</span> <strong>https://www.example.com/wp-login.php</strong>', $html );
		$this->assertStringContainsString( '<div class="notice notice-warning inline"><p>The page sets its own &lt;meta&gt; policy.</p></div>', $html );
		$this->assertStringContainsString( '<caption class="screen-reader-text">Not allowed by the live policy</caption>', $html );
		$this->assertStringContainsString( '<code>https://challenges.cloudflare.com</code><br><span class="description">https://challenges.cloudflare.com/turnstile/v0/api.js</span></td><td>2</td>', $html );
		$this->assertStringContainsString( 'name="context" value="login"><input type="hidden" name="scope" value="site"><input type="hidden" name="directive" value="script-src"><input type="hidden" name="source" value="https://challenges.cloudflare.com"><input type="hidden" name="origin" value="scan"><input type="hidden" name="return" value="scan">', $html );
		$this->assertStringContainsString( '>Allow https://challenges.cloudflare.com in script-src</button>', $html );
		$this->assertStringContainsString( '<tr><td><code>style-src-attr</code></td><td>3 inline blocks</td><td>3</td><td>Allowed now</td></tr>', $html );
		$this->assertStringContainsString( '<tr><td><code>img-src</code></td><td><code>data:</code><br><span class="description">https://img.example.com/a.png</span></td><td>1500</td><td>Allowed now</td></tr>', $html );
		$this->assertSame( 2, substr_count( $html, 'value="forget"' ), 'recent scans can be removed' );
		$this->assertStringContainsString( 'name="url" value="https://www.example.com/wp-login.php"><input type="hidden" name="_wpnonce" value="nonce-codo_csp_scan"><button type="submit" class="button-link">Remove from list</button>', $html );

		$this->assertStringContainsString( '<strong>Hello &lt;world&gt;</strong>', $html );
		$this->assertStringContainsString( '<caption class="screen-reader-text">Not allowed by the draft</caption>', $html );
		$this->assertStringContainsString( '<td>1 inline block</td>', $html );
		$this->assertStringContainsString( '<strong>https://www.example.com/broken/</strong>', $html );
		$this->assertStringContainsString( '<div class="notice notice-error inline"><p>HTTP 500 &lt;oops&gt;</p></div>', $html );
		$this->assertStringNotContainsString( 'None found by the latest scans.', $html );
	}

	public function test_render_scan_result_offers_allow_for_disallowed_draft_issue() {
		$this->options[ PolicyStore::OPTION ]['site']['rules'] = array( self::rule( 'default-src', "'self'" ) );
		ob_start();
		$this->page()->render_scan_result(
			self::scan(
				array(
					'context' => 'weird',
					'status'  => 'issues',
					'draft'   => array(
						self::issue(
							array(
								'directive' => 'style-src-attr',
								'target'    => 'style-src',
								'source'    => "'unsafe-inline'",
								'inline'    => true,
								'count'     => 2,
							)
						),
					),
				)
			),
			'Label',
			false
		);
		$html = ob_get_clean();

		$this->assertStringContainsString( '<td>2 inline blocks</td>', $html );
		$this->assertStringContainsString( 'name="context" value="site"', $html );
		$this->assertStringContainsString( '>Allow &#039;unsafe-inline&#039; in style-src</button>', $html );
		$this->assertStringNotContainsString( 'Remove from list', $html );
		$this->assertStringNotContainsString( 'Not allowed by the live policy', $html );
		$this->assertStringNotContainsString( 'resources found are allowed', $html );
	}

	// ----- settings tab -----

	public function test_settings_tab() {
		$html = $this->render(
			'settings',
			array(
				'upgrade_insecure' => false,
				'scan_on_save'     => false,
				'external_uri'     => 'https://c.example.com/x',
			)
		);

		$this->assertStringContainsString( '<input type="hidden" name="action" value="codo_csp_settings">', $html );
		$this->assertStringContainsString( 'value="nonce-codo_csp_settings"', $html );
		$this->assertStringContainsString( '<label for="codo-csp-login_enabled">Login page</label></th><td><input type="checkbox" id="codo-csp-login_enabled" name="login_enabled" value="1" checked="checked"> ', $html );
		$this->assertStringContainsString( '<input type="checkbox" id="codo-csp-skip_builders" name="skip_builders" value="1" checked="checked">', $html );
		$this->assertStringContainsString( '<input type="checkbox" id="codo-csp-upgrade_insecure" name="upgrade_insecure" value="1"> ', $html );
		$this->assertStringContainsString( '<input type="checkbox" id="codo-csp-scan_on_save" name="scan_on_save" value="1"> ', $html );
		$this->assertStringContainsString( '<input type="checkbox" id="codo-csp-purge_caches" name="purge_caches" value="1" checked="checked">', $html );
		$this->assertStringNotContainsString( ' disabled', $html );
		$this->assertStringNotContainsString( 'type="hidden" name="login_enabled"', $html );
		$this->assertStringContainsString( '<fieldset><label><input type="radio" name="reporting" value="builtin" checked="checked"> Collect them on this site', $html );
		$this->assertStringContainsString( '<label><input type="radio" name="reporting" value="external"> Send them', $html );
		$this->assertStringContainsString( '<label><input type="radio" name="reporting" value="off"> Off</label>', $html );
		$this->assertStringContainsString( 'name="external_uri" value="https://c.example.com/x" placeholder="https://"', $html );
		$this->assertStringNotContainsString( 'Set by CODO_CSP_REPORT_URI', $html );
		$this->assertStringContainsString( '<button type="submit">Save Changes</button></form>', $html );
		$this->assertStringContainsString( '<h2>Configuration in wp-config.php</h2>', $html );
		$this->assertStringContainsString( "define( 'CODO_CSP_LOGIN', false );", $html );
	}

	public function test_settings_tab_external_uri_is_escaped() {
		// A stored value is not re-sanitised on read, so output must escape it.
		$html = $this->render(
			'settings',
			array(
				'reporting'    => Settings::REPORTING_EXTERNAL,
				'external_uri' => 'https://c.example.com/?a="><script>',
			)
		);

		$this->assertStringContainsString( 'value="https://c.example.com/?a=&quot;&gt;&lt;script&gt;"', $html );
		$this->assertStringContainsString( 'value="external" checked="checked"', $html );
		$this->assertStringNotContainsString( '<script>', $html );
	}

	/**
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_settings_tab_locked_by_constants() {
		define( 'CODO_CSP_LOGIN', false );
		define( 'CODO_CSP_REPORT_URI', 'https://collector.example.com/csp' );

		$html = $this->render( 'settings', array( 'login_enabled' => true ) );

		$this->assertStringContainsString( '<td><input type="checkbox" id="codo-csp-login_enabled" name="login_enabled" value="1" disabled> ', $html );
		$this->assertStringNotContainsString( 'type="hidden" name="login_enabled"', $html, 'a locked box posts nothing' );
		$this->assertStringContainsString( '<p class="description">Set in wp-config.php.</p>', $html );
		$this->assertSame( 1, substr_count( $html, 'Set in wp-config.php.' ), 'only the login box is locked' );
		$this->assertStringContainsString( '<input type="checkbox" id="codo-csp-skip_builders" name="skip_builders" value="1" checked="checked"> ', $html );
		$this->assertStringContainsString( '<fieldset disabled>', $html );
		$this->assertStringContainsString( 'value="external" checked="checked"', $html );
		$this->assertStringContainsString( 'name="external_uri" value="https://collector.example.com/csp"', $html );
		$this->assertStringContainsString( '<p class="description">Set by CODO_CSP_REPORT_URI in wp-config.php.</p>', $html );
		$this->assertStringNotContainsString( 'tab=login', $html, 'login tab hidden' );
		$this->assertStringContainsString( 'Reports go to https://collector.example.com/csp.', $html );
	}

	/**
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_settings_tab_locked_login_on() {
		define( 'CODO_CSP_LOGIN', true );

		$html = $this->render( 'settings', array( 'login_enabled' => false ) );

		$this->assertStringContainsString( '<td><input type="checkbox" id="codo-csp-login_enabled" name="login_enabled" value="1" checked="checked" disabled>', $html );
		$this->assertStringNotContainsString( 'type="hidden" name="login_enabled"', $html );
		$this->assertStringContainsString( '<fieldset>', $html );
	}
}
