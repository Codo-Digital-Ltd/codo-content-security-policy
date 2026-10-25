<?php
/**
 * Tests for Scanner, with HTTP functions stubbed and a real seeded policy.
 *
 * @package CodoDigital\Csp\Tests
 */

namespace CodoDigital\Csp\Tests\Unit\Scan;

use Brain\Monkey\Filters;
use Brain\Monkey\Functions;
use CodoDigital\Csp\Http\HeaderSender;
use CodoDigital\Csp\Policy\Policy;
use CodoDigital\Csp\Scan\HtmlParser;
use CodoDigital\Csp\Scan\Scanner;
use CodoDigital\Csp\Settings\PolicyStore;
use CodoDigital\Csp\Settings\Settings;
use CodoDigital\Csp\Tests\TestCase;

class ScannerTest extends TestCase {

	const PAGE = 'https://www.example.com/about/';

	/**
	 * Responses for wp_remote_get, by URL without the scan query argument.
	 *
	 * @var array<string, mixed>
	 */
	private $remote = array();

	/**
	 * Responses for wp_safe_remote_get, by URL.
	 *
	 * @var array<string, mixed>
	 */
	private $safe = array();

	/**
	 * URLs requested, as "function url".
	 *
	 * @var string[]
	 */
	private $requests = array();

	/**
	 * Arguments of each request, in order.
	 *
	 * @var array<int, array<string, mixed>>
	 */
	private $request_args = array();

	/** @var PolicyStore */
	private $store;

	/** @var HeaderSender */
	private $sender;

	protected function setUp(): void {
		parent::setUp();
		$this->remote   = array();
		$this->safe     = array();
		$this->requests = array();
		$this->request_args = array();

		$fetch = function ( $map, $function ) {
			return function ( $url, $args = array() ) use ( $map, $function ) {
				$this->requests[]     = $function . ' ' . $url;
				$this->request_args[] = $args;
				$key              = (string) preg_replace( '/[?&]codo_csp_scan=\d+$/', '', $url );
				$responses        = $this->$map;
				return isset( $responses[ $key ] ) ? $responses[ $key ] : new \WP_Error( 'http_request_failed', 'cURL error 6: Could not resolve host' );
			};
		};

		Functions\stubs(
			array(
				'wp_remote_get'                  => $fetch( 'remote', 'wp_remote_get' ),
				'wp_safe_remote_get'             => $fetch( 'safe', 'wp_safe_remote_get' ),
				'wp_remote_retrieve_response_code' => static function ( $response ) {
					return is_array( $response ) && isset( $response['response']['code'] ) ? $response['response']['code'] : '';
				},
				'wp_remote_retrieve_header'      => static function ( $response, $header ) {
					return is_array( $response ) && isset( $response['headers'][ $header ] ) ? $response['headers'][ $header ] : '';
				},
				'wp_remote_retrieve_body'        => static function ( $response ) {
					return is_array( $response ) && isset( $response['body'] ) ? $response['body'] : '';
				},
			)
		);

		$this->seed();
	}

	/**
	 * Seed settings and the default policies.
	 *
	 * @param string $mode Mode.
	 * @return void
	 */
	private function seed( $mode = Settings::MODE_REPORT_ONLY ) {
		$this->options[ Settings::OPTION ] = array( 'mode' => $mode );
		unset( $this->options[ PolicyStore::OPTION ] );
		$settings    = new Settings();
		$this->store = new PolicyStore( $settings );
		$this->store->seed();
		$this->sender = new HeaderSender(
			$settings,
			$this->store,
			static function () {},
			static function () {
				return false;
			}
		);
	}

	private function scanner() {
		return new Scanner( $this->store, $this->sender, new HtmlParser() );
	}

	/**
	 * A fake HTTP response.
	 *
	 * @param string               $body    Body.
	 * @param int                  $code    Status.
	 * @param array<string, mixed> $headers Headers (lower-case names).
	 * @return array<string, mixed>
	 */
	private static function response( $body, $code = 200, array $headers = array( 'content-type' => 'text/html; charset=UTF-8' ) ) {
		return array(
			'headers'  => $headers,
			'body'     => $body,
			'response' => array( 'code' => $code ),
		);
	}

	private static function html( $body, $head = '' ) {
		return '<!doctype html><html><head>' . $head . '</head><body>' . $body . '</body></html>';
	}

	/**
	 * Issues as "target source count" strings.
	 *
	 * @param array<int, array<string, mixed>> $issues Issues.
	 * @return string[]
	 */
	private static function flat( array $issues ) {
		return array_map(
			static function ( $issue ) {
				return $issue['target'] . ' ' . $issue['source'] . ' ' . $issue['count'] . ( $issue['inline'] ? ' inline' : '' );
			},
			$issues
		);
	}

	public function test_is_own_url() {
		$scanner = $this->scanner();
		$this->assertTrue( $scanner->is_own_url( 'https://www.example.com/x/' ) );
		$this->assertTrue( $scanner->is_own_url( 'http://WWW.EXAMPLE.COM/' ) );
		$this->assertFalse( $scanner->is_own_url( 'https://evil.example.org/' ) );
		$this->assertFalse( $scanner->is_own_url( 'ftp://www.example.com/' ) );
		$this->assertFalse( $scanner->is_own_url( '/relative' ) );
		$this->assertFalse( $scanner->is_own_url( 'data:text/html,hi' ) );
	}

	public function test_is_own_url_ports() {
		$scanner = $this->scanner();
		$this->assertTrue( $scanner->is_own_url( 'https://www.example.com:443/x/' ) );
		$this->assertTrue( $scanner->is_own_url( 'http://www.example.com:80/x/' ) );
		$this->assertFalse( $scanner->is_own_url( 'https://www.example.com:8443/x/' ), 'another port on the same host is another service' );
		$this->assertFalse( $scanner->is_own_url( 'https://example.com/' ) );
	}

	public function test_is_own_url_with_home_on_a_custom_port() {
		Functions\when( 'home_url' )->justReturn( 'https://www.example.com:8443/' );
		$scanner = $this->scanner();
		$this->assertTrue( $scanner->is_own_url( 'https://www.example.com:8443/x/' ) );
		$this->assertTrue( $scanner->is_own_url( 'https://www.example.com/x/' ) );
		$this->assertTrue( $scanner->is_own_url( 'http://www.example.com/x/' ) );
		$this->assertFalse( $scanner->is_own_url( 'https://www.example.com:9000/x/' ) );
	}

	public function test_is_own_url_with_bad_home() {
		Functions\when( 'home_url' )->justReturn( 'nonsense' );
		$this->assertFalse( $this->scanner()->is_own_url( 'https://www.example.com/' ) );
	}

	public function test_context_for() {
		$this->assertSame( 'login', Scanner::context_for( 'https://www.example.com/wp-login.php?action=lostpassword' ) );
		$this->assertSame( 'login', Scanner::context_for( 'https://www.example.com/blog/wp-login.php' ) );
		$this->assertSame( 'site', Scanner::context_for( 'https://www.example.com/my-wp-login.php.html' ) );
		$this->assertSame( 'site', Scanner::context_for( 'https://www.example.com' ) );
		$this->assertSame( 'site', Scanner::context_for( 'https://www.example.com/' ) );
	}

	public function test_without_reporting() {
		$this->assertSame(
			"default-src 'self'; img-src 'self' data:",
			Scanner::without_reporting( "default-src 'self';  report-uri https://x.example/r ; img-src 'self' data:;report-to codo-csp;" )
		);
		$this->assertSame( '', Scanner::without_reporting( '' ) );
		// Only the directive names are stripped, not sources that merely contain them.
		$this->assertSame( 'report-uri-ish x', Scanner::without_reporting( 'report-uri-ish x' ) );
	}

	public function test_other_hosts_are_refused_without_fetching() {
		$result = $this->scanner()->scan( 'https://evil.example.org/' );
		$this->assertSame( 'error', $result['status'] );
		$this->assertSame( 'Only pages on this site can be scanned.', $result['error'] );
		$this->assertSame( 'site', $result['context'] );
		$this->assertSame( array(), $this->requests );
	}

	public function test_fetch_error() {
		$result = $this->scanner()->scan( self::PAGE );
		$this->assertSame( 'error', $result['status'] );
		$this->assertStringContainsString( 'cURL error 6: Could not resolve host', $result['error'] );
		$this->assertCount( 1, $this->requests );
	}

	public function test_request_arguments() {
		$this->scanner()->scan( self::PAGE );
		$this->assertMatchesRegularExpression( '~^wp_remote_get https://www\.example\.com/about/\?codo_csp_scan=\d+$~', $this->requests[0] );
		$args = $this->request_args[0];
		$this->assertSame( 15, $args['timeout'] );
		$this->assertSame( Scanner::MAX_HTML_BYTES, $args['limit_response_size'] );
		$this->assertFalse( $args['sslverify'] );
		$this->assertSame( 'no-cache', $args['headers']['Cache-Control'] );
		$this->assertSame( 'Codo-CSP-Scanner/1.0.0-test', $args['user-agent'] );
	}

	public function test_ssl_verification_follows_the_core_filter() {
		Filters\expectApplied( 'https_local_ssl_verify' )->once()->with( false )->andReturn( true );
		$this->scanner()->scan( self::PAGE );
		$this->assertTrue( $this->request_args[0]['sslverify'] );
		$this->assertSame( 0, $this->request_args[0]['redirection'], 'redirects are followed by hand' );
	}

	public function test_same_site_redirects_are_followed() {
		$this->remote[ self::PAGE ]                          = self::response( '', 301, array( 'location' => '/about-us/' ) );
		$this->remote['https://www.example.com/about-us/']  = self::response( '', 302, array( 'location' => 'http://www.example.com/about-us/final/' ) );
		$this->remote['http://www.example.com/about-us/final/'] = self::response( self::html( '<img src="https://cdn.example.net/a.png">' ) );

		$result = $this->scanner()->scan( self::PAGE );

		$this->assertSame( 'issues', $result['status'] );
		$this->assertSame( self::PAGE, $result['url'] );
		$this->assertSame(
			array(
				'wp_remote_get https://www.example.com/about-us/',
				'wp_remote_get http://www.example.com/about-us/final/',
			),
			array_slice( $this->requests, 1 )
		);
		foreach ( $this->request_args as $args ) {
			$this->assertSame( 0, $args['redirection'] );
			$this->assertFalse( $args['sslverify'] );
		}
	}

	public function test_off_site_redirect_is_not_followed() {
		$this->remote[ self::PAGE ] = self::response( '', 302, array( 'location' => 'https://internal.example.org:8080/admin?x=1' ) );

		$result = $this->scanner()->scan( self::PAGE );

		$this->assertSame( 'error', $result['status'] );
		$this->assertSame( 'The page was not scanned: it redirects off this site, to https://internal.example.org:8080. Only pages on this site are fetched.', $result['error'] );
		$this->assertCount( 1, $this->requests );
	}

	public function test_redirect_to_another_port_is_not_followed() {
		$this->remote[ self::PAGE ] = self::response( '', 307, array( 'location' => 'https://www.example.com:9200/' ) );
		$result                     = $this->scanner()->scan( self::PAGE );
		$this->assertStringContainsString( 'it redirects off this site, to https://www.example.com:9200.', $result['error'] );
		$this->assertCount( 1, $this->requests );
	}

	public function test_redirect_without_location_is_an_error() {
		$this->remote[ self::PAGE ] = self::response( '', 301, array() );
		$result                     = $this->scanner()->scan( self::PAGE );
		$this->assertSame( 'error', $result['status'] );
		$this->assertStringContainsString( 'it redirects without saying where to.', $result['error'] );
		$this->assertCount( 1, $this->requests );
	}

	public function test_too_many_redirects() {
		$this->remote[ self::PAGE ] = self::response( '', 301, array( 'location' => '/r1/' ) );
		for ( $i = 1; $i <= 4; $i++ ) {
			$this->remote[ 'https://www.example.com/r' . $i . '/' ] = self::response( '', 301, array( 'location' => '/r' . ( $i + 1 ) . '/' ) );
		}

		$result = $this->scanner()->scan( self::PAGE );

		$this->assertSame( 'The page was not scanned: too many redirects. Only pages on this site are fetched.', $result['error'] );
		$this->assertCount( 4, $this->requests, 'the page and three redirects' );
		$this->assertSame( 'wp_remote_get https://www.example.com/r3/', $this->requests[3] );
	}

	public function test_three_redirects_are_allowed() {
		$this->remote[ self::PAGE ] = self::response( '', 301, array( 'location' => '/r1/' ) );
		$this->remote['https://www.example.com/r1/'] = self::response( '', 301, array( 'location' => '/r2/' ) );
		$this->remote['https://www.example.com/r2/'] = self::response( '', 301, array( 'location' => '/r3/' ) );
		$this->remote['https://www.example.com/r3/'] = self::response( self::html( '' ) );

		$this->assertSame( 'ok', $this->scanner()->scan( self::PAGE )['status'] );
		$this->assertCount( 4, $this->requests );
	}

	public function test_explicit_context() {
		$this->remote[ self::PAGE ] = self::response( self::html( '<iframe src="https://www.example.com/frame"></iframe>' ) );
		$this->assertSame( 'login', $this->scanner()->scan( self::PAGE, 'login' )['context'] );
		$this->assertSame( 'site', $this->scanner()->scan( self::PAGE, 'bogus' )['context'], 'unknown contexts are guessed from the URL' );

		$login = 'https://www.example.com/wp-login.php';
		$this->remote[ $login ] = self::response( self::html( '' ) );
		$this->assertSame( 'site', $this->scanner()->scan( $login, 'site' )['context'] );
		$this->assertSame( 'login', $this->scanner()->scan( $login, null )['context'] );
	}

	public function test_custom_login_url_uses_login_policy_and_core_header() {
		$this->store->add( 'login', 'img-src', 'https://login-only.example.net' );
		$this->remote[ self::PAGE ] = self::response(
			self::html( '<img src="https://login-only.example.net/a.png">' ),
			200,
			array(
				'content-type'            => 'text/html',
				'content-security-policy' => "frame-ancestors 'self'",
			)
		);

		$login = $this->scanner()->scan( self::PAGE, 'login' );
		$this->assertSame( 'ok', $login['status'] );
		$this->assertSame( array(), $login['warnings'] );

		$site = $this->scanner()->scan( self::PAGE, 'site' );
		$this->assertSame( array( 'img-src https://login-only.example.net 1' ), self::flat( $site['issues'] ) );
		$this->assertCount( 1, $site['warnings'] );
	}

	public function test_non_200() {
		$this->remote[ self::PAGE ] = self::response( 'Not found', 404 );
		$result                     = $this->scanner()->scan( self::PAGE );
		$this->assertSame( 'error', $result['status'] );
		$this->assertSame( 'The page returned HTTP 404.', $result['error'] );
	}

	public function test_non_html() {
		$this->remote[ self::PAGE ] = self::response( '{}', 200, array( 'content-type' => 'application/json' ) );
		$result                     = $this->scanner()->scan( self::PAGE );
		$this->assertSame( 'error', $result['status'] );
		$this->assertSame( 'The page is not HTML.', $result['error'] );
	}

	public function test_missing_content_type_is_treated_as_html() {
		$this->remote[ self::PAGE ] = self::response( self::html( '<img src="/a.png">' ), 200, array() );
		$result                     = $this->scanner()->scan( self::PAGE );
		$this->assertSame( 'ok', $result['status'] );
		$this->assertSame( 1, $result['checked'] );
	}

	public function test_all_ok_page() {
		$this->remote[ self::PAGE ] = self::response(
			self::html(
				'<img src="/logo.png"><img src="data:image/gif;base64,AA"><script>inline()</script><div style="color:red"></div>',
				'<script src="/wp-includes/js/jquery.js"></script>'
			)
		);
		$result = $this->scanner()->scan( self::PAGE );

		$this->assertSame( self::PAGE, $result['url'] );
		$this->assertSame( 'site', $result['context'] );
		$this->assertSame( 'ok', $result['status'] );
		$this->assertSame( '', $result['error'] );
		$this->assertSame( array(), $result['issues'] );
		$this->assertSame( array(), $result['draft'] );
		$this->assertSame( array(), $result['warnings'] );
		$this->assertSame( 3, $result['checked'] );
		$this->assertEqualsWithDelta( time(), $result['time'], 2 );
	}

	public function test_issues_found() {
		$this->remote[ self::PAGE ] = self::response(
			self::html(
				'<img src="https://cdn.example.net/a.png?token=secret"><img src="https://cdn.example.net/b.png">'
				. '<iframe src="https://www.youtube.com/embed/x"></iframe>'
				. '<form action="https://pay.example.net/go"></form>',
				'<script src="https://cdn.example.net/lib.js"></script>'
			)
		);
		$result = $this->scanner()->scan( self::PAGE );

		$this->assertSame( 'issues', $result['status'] );
		$this->assertSame(
			array(
				'script-src https://cdn.example.net 1',
				'img-src https://cdn.example.net 2',
				'frame-src https://www.youtube.com 1',
				'form-action https://pay.example.net 1',
			),
			self::flat( $result['issues'] )
		);
		$this->assertSame( 'https://cdn.example.net/a.png', $result['issues'][1]['example'] );
		$this->assertSame( 'img-src', $result['issues'][1]['directive'] );
		$this->assertSame( 'script-src-elem', $result['issues'][0]['directive'] );
		$this->assertSame( array(), $result['draft'] );
	}

	public function test_inline_issues() {
		$this->store->remove( 'site', 'script-src', "'unsafe-inline'" );
		$this->store->remove( 'site', 'style-src', "'unsafe-inline'" );
		$this->remote[ self::PAGE ] = self::response(
			self::html( '<script>a()</script><script>b()</script><button onclick="x()">x</button><p style="color:red"></p>', '<style>p{}</style>' )
		);
		$result = $this->scanner()->scan( self::PAGE );

		$this->assertSame( 'issues', $result['status'] );
		$this->assertSame(
			array(
				'script-src \'unsafe-inline\' 2 inline',
				'script-src \'unsafe-inline\' 1 inline',
				'style-src \'unsafe-inline\' 1 inline',
				'style-src \'unsafe-inline\' 1 inline',
			),
			self::flat( $result['issues'] )
		);
		$this->assertSame( 'script-src-elem', $result['issues'][0]['directive'] );
		$this->assertSame( '', $result['issues'][0]['example'] );
	}

	public function test_draft_issues_when_enforcing() {
		$this->seed( Settings::MODE_ENFORCE );
		$this->assertSame( 'draft', $this->store->remove( 'site', 'script-src', "'unsafe-inline'" ) );
		$this->remote[ self::PAGE ] = self::response( self::html( '<script>a()</script>' ) );

		$result = $this->scanner()->scan( self::PAGE );
		$this->assertSame( 'issues', $result['status'] );
		$this->assertSame( array(), $result['issues'] );
		$this->assertSame( array( 'script-src \'unsafe-inline\' 1 inline' ), self::flat( $result['draft'] ) );
	}

	public function test_draft_lists_only_issues_the_live_policy_does_not_have() {
		$this->seed( Settings::MODE_ENFORCE );
		$this->store->remove( 'site', 'img-src', 'data:' );
		$this->remote[ self::PAGE ] = self::response( self::html( '<img src="https://cdn.example.net/a.png"><img src="data:image/png;base64,AA">' ) );

		$result = $this->scanner()->scan( self::PAGE );
		$this->assertSame( array( 'img-src https://cdn.example.net 1' ), array_map( static function ( $i ) {
			return $i['directive'] . ' ' . $i['source'] . ' ' . $i['count'];
		}, $result['issues'] ) );
		$this->assertSame( array( 'img-src data:' ), array_map( static function ( $i ) {
			return $i['directive'] . ' ' . $i['source'];
		}, $result['draft'] ) );
	}

	public function test_core_login_frame_ancestors_header_does_not_warn() {
		$url                  = 'https://www.example.com/wp-login.php';
		$this->remote[ $url ] = self::response(
			self::html( '' ),
			200,
			array(
				'content-type'            => 'text/html',
				'content-security-policy' => "frame-ancestors 'self';",
			)
		);
		$this->assertSame( array(), $this->scanner()->scan( $url )['warnings'] );

		// The same header on a front-end page is still reported.
		$this->remote[ self::PAGE ] = self::response( self::html( '' ), 200, array( 'content-type' => 'text/html', 'content-security-policy' => "frame-ancestors 'self';" ) );
		$this->assertCount( 1, $this->scanner()->scan( self::PAGE )['warnings'] );
	}

	public function test_enforcing_without_draft_is_ok() {
		$this->seed( Settings::MODE_ENFORCE );
		$this->remote[ self::PAGE ] = self::response( self::html( '<img src="/a.png">' ) );
		$result                     = $this->scanner()->scan( self::PAGE );
		$this->assertSame( 'ok', $result['status'] );
		$this->assertSame( array(), $result['warnings'] );
	}

	public function test_login_context_uses_login_policy() {
		$url                = 'https://www.example.com/wp-login.php';
		$this->remote[ $url ] = self::response( self::html( '<iframe src="https://www.example.com/frame"></iframe>' ) );
		$result             = $this->scanner()->scan( $url );
		$this->assertSame( 'login', $result['context'] );
		// The login policy has no frame-src, so default-src 'self' covers same-site frames.
		$this->assertSame( 'ok', $result['status'] );
	}

	public function test_own_stylesheets_are_fetched_and_off_site_ones_are_not() {
		$this->remote[ self::PAGE ] = self::response(
			self::html(
				'',
				'<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Inter">'
				. '<link rel="stylesheet" href="/theme.css">'
				. '<link rel="stylesheet" href="/theme.css">'
			)
		);
		$this->remote['https://fonts.googleapis.com/css?family=Inter'] = self::response( '@font-face{src:url(https://fonts.gstatic.com/s/inter.woff2)}', 200, array() );
		$this->remote['https://www.example.com/theme.css']             = self::response( '.a{background:url(https://images.example.net/bg.png)}', 200, array() );

		$result = $this->scanner()->scan( self::PAGE );
		$this->assertSame(
			array(
				'style-src https://fonts.googleapis.com 1',
				'font-src https://fonts.gstatic.com 1',
				'img-src https://images.example.net 1',
			),
			self::flat( $result['issues'] )
		);
		$this->assertSame( 4, $result['checked'] );
		// Only this site is ever requested: Google Fonts' font host is inferred.
		$this->assertSame( array( 'wp_remote_get https://www.example.com/theme.css' ), array_slice( $this->requests, 1 ) );
		$this->assertSame( 'Codo-CSP-Scanner/1.0.0-test', $this->request_args[1]['user-agent'] );
		$this->assertSame( 0, $this->request_args[1]['redirection'] );
		$this->assertSame( 5, $this->request_args[1]['timeout'] );
	}

	public function test_known_font_services_are_inferred_without_requests() {
		$this->remote[ self::PAGE ] = self::response(
			self::html( '', '<link rel="stylesheet" href="https://fonts.bunny.net/css?family=inter">' )
		);

		$result = $this->scanner()->scan( self::PAGE );
		$this->assertSame( array( 'style-src https://fonts.bunny.net 1', 'font-src https://fonts.bunny.net 1' ), self::flat( $result['issues'] ) );
		$this->assertCount( 1, $this->requests );
	}

	public function test_off_site_stylesheets_are_never_requested() {
		$this->remote[ self::PAGE ] = self::response( self::html( '', '<link rel="stylesheet" href="https://cdn.example.net/x.css">' ) );
		$this->remote['https://cdn.example.net/x.css'] = self::response( '.a{background:url(https://images.example.net/bg.png)}' );
		$this->safe['https://cdn.example.net/x.css']   = self::response( '.a{background:url(https://images.example.net/bg.png)}' );

		$result = $this->scanner()->scan( self::PAGE );
		$this->assertSame( array( 'style-src https://cdn.example.net 1' ), self::flat( $result['issues'] ) );
		$this->assertCount( 1, $this->requests );
	}

	public function test_own_stylesheet_does_not_follow_off_site_redirects() {
		$this->remote[ self::PAGE ]                          = self::response( self::html( '', '<link rel="stylesheet" href="/theme.css">' ) );
		$this->remote['https://www.example.com/theme.css'] = self::response( '', 302, array( 'location' => 'https://evil.example.org/x.css' ) );
		$this->remote['https://evil.example.org/x.css']    = self::response( '.a{background:url(https://images.example.net/bg.png)}', 200, array() );

		$result = $this->scanner()->scan( self::PAGE );
		$this->assertSame( array(), $result['issues'] );
		$this->assertSame( array( 'wp_remote_get https://www.example.com/theme.css' ), array_slice( $this->requests, 1 ) );
	}

	public function test_own_stylesheet_follows_same_site_redirects() {
		$this->remote[ self::PAGE ]                          = self::response( self::html( '', '<link rel="stylesheet" href="/theme.css">' ) );
		$this->remote['https://www.example.com/theme.css'] = self::response( '', 301, array( 'location' => '/theme.min.css' ) );
		$this->remote['https://www.example.com/theme.min.css'] = self::response( '.a{background:url(https://images.example.net/bg.png)}', 200, array() );

		$result = $this->scanner()->scan( self::PAGE );
		$this->assertSame( array( 'img-src https://images.example.net 1' ), self::flat( $result['issues'] ) );
	}

	/**
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_time_budget_caps_timeouts_and_stops_fetching_stylesheets() {
		$clock = array( 1000.0, 1010.0, 1012.0, 1018.0, 1020.0 );
		Functions\when( 'CodoDigital\\Csp\\Scan\\microtime' )->alias(
			static function () use ( &$clock ) {
				return count( $clock ) > 1 ? array_shift( $clock ) : $clock[0];
			}
		);
		$this->remote[ self::PAGE ] = self::response(
			self::html( '', '<link rel="stylesheet" href="/a.css"><link rel="stylesheet" href="/b.css"><link rel="stylesheet" href="/c.css">' )
		);
		$this->remote['https://www.example.com/a.css'] = self::response( '.a{background:url(https://images.example.net/a.png)}', 200, array() );
		$this->remote['https://www.example.com/b.css'] = self::response( '.b{background:url(https://images.example.net/b.png)}', 200, array() );

		$result = $this->scanner()->scan( self::PAGE );

		// 1000: deadline 1020. 1010: page gets min(15, 10). 1012: a.css starts.
		// 1018: a.css gets 2 s. 1020: out of time before b.css.
		$this->assertSame( 10, $this->request_args[0]['timeout'] );
		$this->assertSame( 2, $this->request_args[1]['timeout'] );
		$this->assertSame( array( 'wp_remote_get https://www.example.com/a.css' ), array_slice( $this->requests, 1 ) );
		$this->assertSame( array( 'img-src https://images.example.net 1' ), self::flat( $result['issues'] ) );
	}

	public function test_failed_stylesheets_add_nothing() {
		$this->remote[ self::PAGE ] = self::response(
			self::html(
				'',
				'<link rel="stylesheet" href="/missing.css">'
				. '<link rel="stylesheet" href="/gone.css">'
				. '<link rel="stylesheet" href="ftp://www.example.com/x.css">'
				. '<link rel="stylesheet" href="data:text/css,a{}">'
				. '<link rel="stylesheet" href="weird:thing">'
			)
		);
		$this->remote['https://www.example.com/missing.css'] = self::response( 'a{background:url(https://images.example.net/x.png)}', 404 );

		$result = $this->scanner()->scan( self::PAGE );
		$this->assertSame(
			array( 'wp_remote_get https://www.example.com/missing.css', 'wp_remote_get https://www.example.com/gone.css' ),
			array_slice( $this->requests, 1 )
		);
		foreach ( $result['issues'] as $issue ) {
			$this->assertNotSame( 'https://images.example.net', $issue['source'] );
		}
	}

	public function test_at_most_ten_stylesheets_are_fetched() {
		$links = '';
		for ( $i = 0; $i < 12; $i++ ) {
			$links .= '<link rel="stylesheet" href="/s' . $i . '.css">';
		}
		$this->remote[ self::PAGE ] = self::response( self::html( '', $links ) );
		$this->scanner()->scan( self::PAGE );
		$this->assertCount( 1 + Scanner::MAX_STYLESHEETS, $this->requests );
	}

	public function test_foreign_policy_header_warns() {
		$this->remote[ self::PAGE ] = self::response(
			self::html( '' ),
			200,
			array(
				'content-type'            => 'text/html',
				'content-security-policy' => "default-src 'none'",
			)
		);
		$result = $this->scanner()->scan( self::PAGE );
		$this->assertCount( 1, $result['warnings'] );
		$this->assertStringContainsString( "A different Content-Security-Policy header was received: default-src 'none'.", $result['warnings'][0] );
		$this->assertSame( 'ok', $result['status'] );
	}

	public function test_own_header_does_not_warn_even_with_old_reporting() {
		$ours                       = $this->sender->build( 'site' )['Content-Security-Policy-Report-Only'][0];
		$this->remote[ self::PAGE ] = self::response(
			self::html( '' ),
			200,
			array(
				'content-type'                        => 'text/html',
				'content-security-policy-report-only' => $ours . '; report-uri https://www.example.com/?codo_csp_report=old; report-to codo-csp',
			)
		);
		$this->assertSame( array(), $this->scanner()->scan( self::PAGE )['warnings'] );
	}

	public function test_array_header_values_are_checked_one_by_one() {
		$ours                       = $this->sender->build( 'site' )['Content-Security-Policy-Report-Only'][0];
		$long                       = "script-src 'none'; " . str_repeat( 'x', 400 );
		$this->remote[ self::PAGE ] = self::response(
			self::html( '' ),
			200,
			array(
				'content-type'                        => 'text/html',
				'content-security-policy-report-only' => array( $ours, $long ),
			)
		);
		$warnings = $this->scanner()->scan( self::PAGE )['warnings'];
		$this->assertCount( 1, $warnings );
		$this->assertStringContainsString( 'Content-Security-Policy-Report-Only', $warnings[0] );
		// The quoted value is truncated to 300 characters.
		$this->assertStringContainsString( mb_substr( $long, 0, 300 ) . '.', $warnings[0] );
		$this->assertStringNotContainsString( mb_substr( $long, 0, 301 ), $warnings[0] );
	}

	public function test_oversized_headers_warn() {
		Filters\expectApplied( 'codo_csp_headers' )->andReturnUsing(
			static function ( $headers ) {
				$headers['Content-Security-Policy-Report-Only'][] = "img-src 'self' " . str_repeat( 'https://a.example.net ', 200 );
				return $headers;
			}
		);
		$this->remote[ self::PAGE ] = self::response( self::html( '' ) );
		$warnings                   = $this->scanner()->scan( self::PAGE )['warnings'];
		$this->assertCount( 1, $warnings );
		$this->assertStringContainsString( 'over 4 KB', $warnings[0] );
	}

	public function test_no_headers_when_disabled_by_filter() {
		Filters\expectApplied( 'codo_csp_headers' )->andReturn( array() );
		$this->remote[ self::PAGE ] = self::response(
			self::html( '' ),
			200,
			array(
				'content-type'                        => 'text/html',
				'content-security-policy-report-only' => "default-src 'self'",
			)
		);
		$this->assertCount( 1, $this->scanner()->scan( self::PAGE )['warnings'] );
	}

	public function test_evaluate_marks_page_origin_as_self_and_skips_unparseable() {
		$policy = new Policy(
			array(
				array(
					'd' => 'img-src',
					's' => 'https://cdn.example.net',
				),
			)
		);
		$issues = $this->scanner()->evaluate(
			$policy,
			array(
				array(
					'directive' => 'img-src',
					'url'       => 'https://www.example.com/a.png#frag',
				),
				array(
					'directive' => 'img-src',
					'url'       => 'weird:thing',
				),
				array(
					'directive' => 'img-src',
					'url'       => 'https://cdn.example.net/ok.png',
				),
			),
			array(
				'script-src-elem' => 3,
				'style-src-attr'  => 0,
			),
			'https://www.example.com'
		);
		$this->assertSame(
			array(
				array(
					'directive' => 'img-src',
					'target'    => 'img-src',
					'source'    => "'self'",
					'example'   => 'https://www.example.com/a.png',
					'count'     => 1,
					'inline'    => false,
				),
			),
			$issues
		);
	}
}
