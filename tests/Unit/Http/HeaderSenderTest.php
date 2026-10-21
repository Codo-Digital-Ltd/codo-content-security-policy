<?php
/**
 * Tests for HeaderSender: header building, skipping and emitting.
 *
 * @package CodoDigital\Csp\Tests
 */

namespace CodoDigital\Csp\Tests\Unit\Http;

use Brain\Monkey\Filters;
use Brain\Monkey\Functions;
use CodoDigital\Csp\Http\HeaderSender;
use CodoDigital\Csp\Settings\PolicyStore;
use CodoDigital\Csp\Settings\Settings;
use CodoDigital\Csp\Tests\TestCase;

class HeaderSenderTest extends TestCase {

	const NOW = 1700000000;

	/**
	 * Emitted header lines.
	 *
	 * @var string[]
	 */
	private $emitted = array();

	/**
	 * What the headers_sent double returns.
	 *
	 * @var bool
	 */
	private $sent = false;

	/**
	 * REQUEST_URI before the test.
	 *
	 * @var string|null
	 */
	private $request_uri;

	protected function setUp(): void {
		parent::setUp();
		$this->emitted     = array();
		$this->sent        = false;
		$_GET              = array();
		$this->request_uri = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : null;
		unset( $_SERVER['REQUEST_URI'] );
		Functions\when( 'is_customize_preview' )->justReturn( false );
	}

	protected function tearDown(): void {
		$_GET = array();
		if ( null === $this->request_uri ) {
			unset( $_SERVER['REQUEST_URI'] );
		} else {
			$_SERVER['REQUEST_URI'] = $this->request_uri;
		}
		parent::tearDown();
	}

	/**
	 * Store the policy option.
	 *
	 * @param array<int, array<string, string>>      $site  Site rules.
	 * @param array<int, array<string, string>>|null $draft Site draft rules.
	 * @return void
	 */
	private function policies( array $site, $draft = null ) {
		$this->options[ PolicyStore::OPTION ] = array(
			'site'  => array(
				'rules' => $site,
				'draft' => null === $draft ? null : array(
					'rules' => $draft,
					't'     => self::NOW,
				),
			),
			'login' => array(
				'rules' => array(
					array(
						'd' => 'form-action',
						's' => "'self'",
					),
				),
				'draft' => null,
			),
		);
	}

	/**
	 * Sender with recorded output and the given settings.
	 *
	 * @param array<string, mixed> $settings Stored settings.
	 * @param Settings|null        $object   Settings object to use instead.
	 * @return HeaderSender
	 */
	private function sender( array $settings = array(), $object = null ) {
		$this->options[ Settings::OPTION ] = $settings;
		$object                            = null !== $object ? $object : new Settings();
		return new HeaderSender(
			$object,
			new PolicyStore( $object ),
			function ( $line ) {
				$this->emitted[] = $line;
			},
			function () {
				return $this->sent;
			}
		);
	}

	private function rule( $directive, $source ) {
		return array(
			'd' => $directive,
			's' => $source,
		);
	}

	public function test_register_hooks() {
		$sender = $this->sender();
		$sender->register();
		$this->assertNotFalse( has_action( 'send_headers', array( $sender, 'send_front' ) ) );
		$this->assertNotFalse( has_action( 'login_init', array( $sender, 'send_login' ) ) );
	}

	public function test_default_emitters_are_used_without_doubles() {
		$settings = new Settings();
		$sender   = new HeaderSender( $settings, new PolicyStore( $settings ) );
		$this->assertInstanceOf( HeaderSender::class, $sender );
		$this->assertSame( array(), $this->emitted );
	}

	public function test_report_only_without_reporting() {
		$this->policies( array( $this->rule( 'default-src', "'self'" ) ) );
		$headers = $this->sender(
			array(
				'reporting'        => Settings::REPORTING_OFF,
				'upgrade_insecure' => true,
			)
		)->build( 'site', self::NOW );
		$this->assertSame( array( 'Content-Security-Policy-Report-Only' => array( "default-src 'self'" ) ), $headers, 'no upgrade-insecure-requests in report-only' );
	}

	public function test_report_only_with_builtin_reporting() {
		$this->policies( array( $this->rule( 'img-src', 'data:' ) ) );
		$headers = $this->sender(
			array(
				'reporting'    => Settings::REPORTING_BUILTIN,
				'report_until' => self::NOW + 10,
				'report_token' => 'tok',
			)
		)->build( 'site', self::NOW );
		$uri     = 'https://www.example.com/?codo_csp_report=tok';
		$this->assertSame(
			array(
				'Content-Security-Policy-Report-Only' => array( 'img-src data:; report-uri ' . $uri . '; report-to codo-csp' ),
				'Reporting-Endpoints'                 => array( 'codo-csp="' . $uri . '"' ),
			),
			$headers
		);
	}

	public function test_enforce_with_upgrade_and_external_reporting() {
		$this->policies( array( $this->rule( 'default-src', "'self'" ) ) );
		$headers = $this->sender(
			array(
				'mode'             => Settings::MODE_ENFORCE,
				'reporting'        => Settings::REPORTING_EXTERNAL,
				'external_uri'     => 'https://c.example.com/r',
				'upgrade_insecure' => true,
			)
		)->build( 'site', self::NOW );
		$this->assertSame(
			array(
				'Content-Security-Policy' => array( "default-src 'self'; upgrade-insecure-requests; report-uri https://c.example.com/r; report-to codo-csp" ),
				'Reporting-Endpoints'     => array( 'codo-csp="https://c.example.com/r"' ),
			),
			$headers
		);
	}

	public function test_enforce_without_upgrade() {
		$this->policies( array( $this->rule( 'default-src', "'self'" ) ) );
		$headers = $this->sender(
			array(
				'mode'      => Settings::MODE_ENFORCE,
				'reporting' => Settings::REPORTING_OFF,
			)
		)->build( 'site', self::NOW );
		$this->assertSame( array( 'Content-Security-Policy' => array( "default-src 'self'" ) ), $headers );
	}

	public function test_enforce_with_draft_sends_both_headers() {
		$this->policies(
			array( $this->rule( 'default-src', "'self'" ) ),
			array( $this->rule( 'default-src', "'self'" ), $this->rule( 'img-src', 'https:' ) )
		);
		$headers = $this->sender(
			array(
				'mode'             => Settings::MODE_ENFORCE,
				'reporting'        => Settings::REPORTING_EXTERNAL,
				'external_uri'     => 'https://c.example.com/r',
				'upgrade_insecure' => true,
			)
		)->build( 'site', self::NOW );
		$extra   = '; report-uri https://c.example.com/r; report-to codo-csp';
		$this->assertSame( array( "default-src 'self'; upgrade-insecure-requests" . $extra ), $headers['Content-Security-Policy'] );
		$this->assertSame( array( "default-src 'self'; img-src https:" . $extra ), $headers['Content-Security-Policy-Report-Only'], 'draft never upgrades' );
		$this->assertArrayHasKey( 'Reporting-Endpoints', $headers );
	}

	public function test_draft_ignored_in_report_only() {
		$this->policies(
			array( $this->rule( 'default-src', "'self'" ) ),
			array( $this->rule( 'img-src', 'https:' ) )
		);
		$headers = $this->sender( array( 'reporting' => Settings::REPORTING_OFF ) )->build( 'site', self::NOW );
		$this->assertSame( array( 'Content-Security-Policy-Report-Only' => array( "default-src 'self'" ) ), $headers );
	}

	public function test_login_reports_are_marked_with_their_context() {
		$this->policies( array( $this->rule( 'default-src', "'self'" ) ) );
		$headers = $this->sender(
			array(
				'reporting'    => Settings::REPORTING_BUILTIN,
				'report_until' => self::NOW + 10,
				'report_token' => 'tok',
			)
		)->build( 'login', self::NOW );
		$uri     = 'https://www.example.com/?codo_csp_report=tok&ctx=login';
		$this->assertSame( array( "form-action 'self'; report-uri " . $uri . '; report-to codo-csp' ), $headers['Content-Security-Policy-Report-Only'] );
		$this->assertSame( array( 'codo-csp="' . $uri . '"' ), $headers['Reporting-Endpoints'] );
	}

	/**
	 * @return array<string, array{0: array<string, string>, 1: string|null, 2: bool}>
	 */
	public function embed_requests() {
		return array(
			'embed query arg'         => array( array( 'embed' => 'true' ), '/?p=12', true ),
			'pretty embed'            => array( array(), '/2026/10/hello/embed/', true ),
			'no trailing slash'       => array( array(), '/hello/embed', true ),
			'embed with query'        => array( array(), '/hello/embed/?x=1', true ),
			'embed as a page slug'    => array( array(), '/embed/', true ),
			'embedded slug'           => array( array(), '/embedded/', false ),
			'embed in the middle'     => array( array(), '/embed/other/', false ),
			'embed-like slug'         => array( array(), '/hello/my-embed/', false ),
			'embed only in the query' => array( array(), '/hello/?x=/embed/', false ),
			'plain page'              => array( array(), '/hello/', false ),
			'no request uri'          => array( array(), null, false ),
		);
	}

	/**
	 * @dataProvider embed_requests
	 */
	public function test_is_embed_request( array $get, $uri, $expected ) {
		$_GET = $get;
		if ( null !== $uri ) {
			$_SERVER['REQUEST_URI'] = $uri;
		}
		$this->assertSame( $expected, $this->sender()->is_embed_request() );
	}

	public function test_embeds_drop_frame_ancestors_from_live_and_draft() {
		$_SERVER['REQUEST_URI'] = '/hello/embed/';
		$this->policies(
			array( $this->rule( 'default-src', "'self'" ), $this->rule( 'frame-ancestors', "'self'" ) ),
			array( $this->rule( 'default-src', "'self'" ), $this->rule( 'frame-ancestors', "'none'" ) )
		);
		$headers = $this->sender(
			array(
				'mode'      => Settings::MODE_ENFORCE,
				'reporting' => Settings::REPORTING_OFF,
			)
		)->build( 'site', self::NOW );
		$this->assertSame(
			array(
				'Content-Security-Policy'             => array( "default-src 'self'" ),
				'Content-Security-Policy-Report-Only' => array( "default-src 'self'" ),
			),
			$headers
		);
	}

	public function test_embeds_without_draft_drop_frame_ancestors() {
		$_GET['embed'] = '1';
		$this->policies( array( $this->rule( 'default-src', "'self'" ), $this->rule( 'frame-ancestors', "'self'" ) ) );
		$headers = $this->sender(
			array(
				'mode'      => Settings::MODE_ENFORCE,
				'reporting' => Settings::REPORTING_OFF,
			)
		)->build( 'site', self::NOW );
		$this->assertSame( array( 'Content-Security-Policy' => array( "default-src 'self'" ) ), $headers );
	}

	public function test_non_embeds_keep_frame_ancestors() {
		$_SERVER['REQUEST_URI'] = '/hello/';
		$this->policies( array( $this->rule( 'default-src', "'self'" ), $this->rule( 'frame-ancestors', "'self'" ) ) );
		$headers = $this->sender( array( 'reporting' => Settings::REPORTING_OFF ) )->build( 'site', self::NOW );
		$this->assertSame( array( "default-src 'self'; frame-ancestors 'self'" ), $headers['Content-Security-Policy-Report-Only'] );
	}

	public function test_login_keeps_frame_ancestors_even_on_an_embed_url() {
		$_GET['embed'] = '1';
		$this->policies( array() );
		$this->options[ PolicyStore::OPTION ]['login']['rules'][] = $this->rule( 'frame-ancestors', "'self'" );
		$headers = $this->sender( array( 'reporting' => Settings::REPORTING_OFF ) )->build( 'login', self::NOW );
		$this->assertSame( array( "form-action 'self'; frame-ancestors 'self'" ), $headers['Content-Security-Policy-Report-Only'] );
	}

	public function test_login_context_uses_login_policy() {
		$this->policies( array( $this->rule( 'default-src', "'self'" ) ) );
		$headers = $this->sender( array( 'reporting' => Settings::REPORTING_OFF ) )->build( 'login', self::NOW );
		$this->assertSame( array( "form-action 'self'" ), $headers['Content-Security-Policy-Report-Only'] );
	}

	public function test_disabled_builds_nothing() {
		$this->policies( array( $this->rule( 'default-src', "'self'" ) ) );
		$settings = \Mockery::mock( Settings::class )->makePartial();
		$settings->shouldReceive( 'is_disabled' )->andReturn( true );
		Filters\expectApplied( 'codo_csp_headers' )->never();
		$sender = $this->sender( array(), $settings );
		$this->assertSame( array(), $sender->build( 'site' ) );

		$sender->send_front();
		$sender->send_login();
		$this->assertSame( array(), $this->emitted );
	}

	public function test_headers_filter_can_change_headers() {
		$this->policies( array( $this->rule( 'default-src', "'self'" ) ) );
		Filters\expectApplied( 'codo_csp_headers' )->once()->with( \Mockery::type( 'array' ), 'site' )->andReturn( array( 'X-Test' => array( 'yes' ) ) );
		$this->assertSame( array( 'X-Test' => array( 'yes' ) ), $this->sender( array( 'reporting' => Settings::REPORTING_OFF ) )->build( 'site', self::NOW ) );
	}

	public function test_headers_filter_returning_non_array_is_ignored() {
		$this->policies( array( $this->rule( 'default-src', "'self'" ) ) );
		Filters\expectApplied( 'codo_csp_headers' )->once()->andReturn( false );
		$this->assertSame(
			array( 'Content-Security-Policy-Report-Only' => array( "default-src 'self'" ) ),
			$this->sender( array( 'reporting' => Settings::REPORTING_OFF ) )->build( 'site', self::NOW )
		);
	}

	public function test_send_front_emits_headers() {
		$this->policies( array( $this->rule( 'default-src', "'self'" ) ) );
		$this->sender( array( 'reporting' => Settings::REPORTING_OFF ) )->send_front();
		$this->assertSame( array( "Content-Security-Policy-Report-Only: default-src 'self'" ), $this->emitted );
	}

	public function test_send_front_emits_every_value_and_strips_line_breaks() {
		Filters\expectApplied( 'codo_csp_headers' )->andReturn(
			array(
				'Content-Security-Policy' => array( "default-src 'self'\r\nSet-Cookie: evil=1", '', "\r\n" ),
				'X-Single'                => 'scalar',
			)
		);
		$this->sender( array( 'reporting' => Settings::REPORTING_OFF ) )->send_front();
		$this->assertSame(
			array(
				"Content-Security-Policy: default-src 'self'Set-Cookie: evil=1",
				'X-Single: scalar',
			),
			$this->emitted,
			'line breaks removed, empty values skipped'
		);
	}

	public function test_nothing_emitted_when_headers_already_sent() {
		$this->policies( array( $this->rule( 'default-src', "'self'" ) ) );
		$this->sent = true;
		$sender     = $this->sender( array( 'reporting' => Settings::REPORTING_OFF ) );
		$sender->send_front();
		$sender->send_login();
		$this->assertSame( array(), $this->emitted );
	}

	public function test_nothing_emitted_when_filter_empties_headers() {
		Filters\expectApplied( 'codo_csp_headers' )->andReturn( array() );
		$sent   = false;
		$sender = new HeaderSender(
			new Settings(),
			new PolicyStore( new Settings() ),
			function ( $line ) {
				$this->emitted[] = $line;
			},
			static function () use ( &$sent ) {
				$sent = true;
				return false;
			}
		);
		$sender->send_front();
		$this->assertSame( array(), $this->emitted );
		$this->assertFalse( $sent, 'headers_sent not consulted for empty headers' );
	}

	public function test_send_login_when_enabled() {
		$this->policies( array() );
		$this->sender( array( 'reporting' => Settings::REPORTING_OFF ) )->send_login();
		$this->assertSame( array( "Content-Security-Policy-Report-Only: form-action 'self'" ), $this->emitted );
	}

	public function test_send_login_when_disabled() {
		$this->policies( array() );
		Filters\expectApplied( 'codo_csp_headers' )->never();
		$this->sender(
			array(
				'login_enabled' => false,
				'reporting'     => Settings::REPORTING_OFF,
			)
		)->send_login();
		$this->assertSame( array(), $this->emitted );
	}

	public function test_customize_preview_is_a_builder_request() {
		Functions\when( 'is_customize_preview' )->justReturn( true );
		Functions\expect( 'current_user_can' )->never();
		$sender = $this->sender();
		$this->assertTrue( $sender->is_builder_request() );
		$this->assertTrue( $sender->should_skip_front() );
	}

	/**
	 * @dataProvider builder_args
	 */
	public function test_builder_query_arg_for_editor( $arg ) {
		$_GET[ $arg ] = '1';
		Functions\expect( 'current_user_can' )->once()->with( 'edit_posts' )->andReturn( true );
		$this->assertTrue( $this->sender()->is_builder_request() );
	}

	public function builder_args() {
		$args = array();
		foreach ( HeaderSender::BUILDER_QUERY_ARGS as $arg ) {
			$args[ $arg ] = array( $arg );
		}
		return $args;
	}

	public function test_builder_query_arg_for_visitor_is_not_skipped() {
		$_GET['elementor-preview'] = '1';
		Functions\expect( 'current_user_can' )->once()->with( 'edit_posts' )->andReturn( false );
		$sender = $this->sender();
		$this->assertFalse( $sender->should_skip_front() );
	}

	public function test_plain_request_is_not_a_builder_request() {
		$_GET['s'] = 'search';
		Functions\expect( 'current_user_can' )->never();
		$this->assertFalse( $this->sender()->is_builder_request() );
	}

	public function test_builder_request_skips_front_headers() {
		$this->policies( array( $this->rule( 'default-src', "'self'" ) ) );
		$_GET['et_fb'] = '1';
		Functions\when( 'current_user_can' )->justReturn( true );
		$this->sender( array( 'reporting' => Settings::REPORTING_OFF ) )->send_front();
		$this->assertSame( array(), $this->emitted );
	}

	public function test_builder_request_not_skipped_when_setting_off() {
		$this->policies( array( $this->rule( 'default-src', "'self'" ) ) );
		$_GET['et_fb'] = '1';
		Functions\expect( 'current_user_can' )->never();
		$sender = $this->sender(
			array(
				'skip_builders' => false,
				'reporting'     => Settings::REPORTING_OFF,
			)
		);
		$this->assertFalse( $sender->should_skip_front() );
		$sender->send_front();
		$this->assertCount( 1, $this->emitted );
	}

	public function test_skip_request_filter() {
		$this->policies( array( $this->rule( 'default-src', "'self'" ) ) );
		Filters\expectApplied( 'codo_csp_skip_request' )->once()->with( false )->andReturn( 1 );
		$sender = $this->sender( array( 'reporting' => Settings::REPORTING_OFF ) );
		$sender->send_front();
		$this->assertSame( array(), $this->emitted );
	}

	public function test_skip_request_filter_can_unskip() {
		$_GET['fl_builder'] = '';
		Functions\when( 'current_user_can' )->justReturn( true );
		Filters\expectApplied( 'codo_csp_skip_request' )->once()->with( true )->andReturn( false );
		$this->assertFalse( $this->sender()->should_skip_front() );
	}
}
