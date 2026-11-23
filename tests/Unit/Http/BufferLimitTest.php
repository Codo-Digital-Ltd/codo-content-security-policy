<?php
/**
 * Tests for BufferLimit.
 *
 * @package CodoDigital\Csp\Tests
 */

namespace CodoDigital\Csp\Tests\Unit\Http;

use Brain\Monkey\Filters;
use CodoDigital\Csp\Http\BufferLimit;
use CodoDigital\Csp\Tests\TestCase;

/**
 * BufferLimit tests.
 */
class BufferLimitTest extends TestCase {

	/**
	 * SERVER_SOFTWARE before the test, or null.
	 *
	 * @var string|null
	 */
	private $software;

	protected function setUp(): void {
		parent::setUp();
		$this->software = isset( $_SERVER['SERVER_SOFTWARE'] ) ? $_SERVER['SERVER_SOFTWARE'] : null;
		unset( $_SERVER['SERVER_SOFTWARE'] );
	}

	protected function tearDown(): void {
		if ( null === $this->software ) {
			unset( $_SERVER['SERVER_SOFTWARE'] );
		} else {
			$_SERVER['SERVER_SOFTWARE'] = $this->software;
		}
		parent::tearDown();
	}

	public function test_parse_size_units() {
		$this->assertSame( 4096, BufferLimit::parse_size( '4096' ) );
		$this->assertSame( 32768, BufferLimit::parse_size( '32k' ) );
		$this->assertSame( 16384, BufferLimit::parse_size( '16K' ) );
		$this->assertSame( 1048576, BufferLimit::parse_size( '1m' ) );
		$this->assertSame( 2097152, BufferLimit::parse_size( ' 2M ' ) );
		$this->assertSame( 0, BufferLimit::parse_size( '4g' ) );
		$this->assertSame( 0, BufferLimit::parse_size( '$size' ) );
		$this->assertSame( 0, BufferLimit::parse_size( '' ) );
	}

	public function test_detect_takes_smallest_and_follows_includes() {
		$dir = dirname( __DIR__, 2 ) . '/fixtures/nginx';
		// 32k in nginx.conf, 16K in an included conf.d file, 1m in a quoted
		// include that includes nginx.conf again; the commented 1k and
		// proxy_buffer_size are ignored.
		$this->assertSame( 16384, BufferLimit::detect( array( $dir . '/nginx.conf' ) ) );
		$this->assertSame( 1048576, BufferLimit::detect( array( $dir . '/snippets/php.conf' ) ) );
	}

	public function test_detect_without_readable_config() {
		$this->assertSame( 0, BufferLimit::detect( array( '/nonexistent/nginx/nginx.conf', '/nonexistent/nginx/conf.d/*.conf' ) ) );
	}

	public function test_path_allowed_follows_open_basedir() {
		$this->assertTrue( BufferLimit::path_allowed( '/etc/nginx/nginx.conf', '' ) );
		$this->assertFalse( BufferLimit::path_allowed( '/etc/nginx/nginx.conf', '/var/www' . PATH_SEPARATOR . '/tmp' ) );
		$this->assertTrue( BufferLimit::path_allowed( '/etc/nginx/nginx.conf', '/var/www' . PATH_SEPARATOR . '/etc/nginx' ) );
	}

	public function test_filter_sets_the_size() {
		Filters\expectApplied( 'codo_csp_header_buffer_size' )->once()->with( 0 )->andReturn( 32768 );
		$_SERVER['SERVER_SOFTWARE'] = 'nginx/1.30.0';
		$this->assertSame( array( 32768, BufferLimit::SOURCE_CONFIGURED ), BufferLimit::resolve() );
		$this->assertArrayNotHasKey( BufferLimit::TRANSIENT, $this->transients, 'no detection when configured' );
	}

	/**
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_constant_sets_the_size_and_filter_overrides_it() {
		define( 'CODO_CSP_HEADER_BUFFER_SIZE', 16384 );
		$this->assertSame( array( 16384, BufferLimit::SOURCE_CONFIGURED ), BufferLimit::resolve() );

		Filters\expectApplied( 'codo_csp_header_buffer_size' )->with( 16384 )->andReturn( 65536 );
		$this->assertSame( array( 65536, BufferLimit::SOURCE_CONFIGURED ), BufferLimit::resolve() );
	}

	public function test_nginx_uses_cached_detection() {
		$_SERVER['SERVER_SOFTWARE']                  = 'nginx/1.30.0';
		$this->transients[ BufferLimit::TRANSIENT ] = '32768';
		$this->assertSame( array( 32768, BufferLimit::SOURCE_DETECTED ), BufferLimit::resolve() );
	}

	public function test_nginx_without_detected_size_assumes_default() {
		$_SERVER['SERVER_SOFTWARE']                  = 'NGINX';
		$this->transients[ BufferLimit::TRANSIENT ] = 0;
		$this->assertSame( array( 4096, BufferLimit::SOURCE_NGINX_DEFAULT ), BufferLimit::resolve() );
	}

	public function test_nginx_detection_is_cached() {
		$_SERVER['SERVER_SOFTWARE'] = 'nginx';
		BufferLimit::resolve();
		$this->assertArrayHasKey( BufferLimit::TRANSIENT, $this->transients );
		$this->assertIsInt( $this->transients[ BufferLimit::TRANSIENT ] );
	}

	public function test_apache_and_litespeed_assume_8kb() {
		foreach ( array( 'Apache/2.4.62 (Debian)', 'LiteSpeed' ) as $software ) {
			$_SERVER['SERVER_SOFTWARE'] = $software;
			$this->assertSame( array( 8192, BufferLimit::SOURCE_SERVER_DEFAULT ), BufferLimit::resolve() );
		}
		$this->assertArrayNotHasKey( BufferLimit::TRANSIENT, $this->transients );
	}

	public function test_unknown_server_assumes_nginx_default() {
		$this->assertSame( array( 4096, BufferLimit::SOURCE_NGINX_DEFAULT ), BufferLimit::resolve() );
		$_SERVER['SERVER_SOFTWARE'] = 'Caddy';
		$this->assertSame( array( 4096, BufferLimit::SOURCE_NGINX_DEFAULT ), BufferLimit::resolve() );
	}

	public function test_check_warns_within_headroom_of_the_limit() {
		list( $warn, $message ) = BufferLimit::check( 3073 );
		$this->assertTrue( $warn );
		$this->assertSame( 'Policy headers are 3073 B, close to or over this server\'s 4096 B FastCGI header buffer (assumed NGINX default). Remove sources you no longer need, raise fastcgi_buffer_size, or set the real size with the codo_csp_header_buffer_size filter.', $message );

		list( $warn, $message ) = BufferLimit::check( 3072 );
		$this->assertFalse( $warn );
		$this->assertSame( 'Policy headers are 3072 B. This server\'s FastCGI header buffer is 4096 B (assumed NGINX default), so this is within limits.', $message );
	}

	public function test_check_within_detected_limit() {
		$_SERVER['SERVER_SOFTWARE']                  = 'nginx';
		$this->transients[ BufferLimit::TRANSIENT ] = 32768;
		list( $warn, $message ) = BufferLimit::check( 4150 );
		$this->assertFalse( $warn );
		$this->assertStringContainsString( '32768 B (detected from nginx config), so this is within limits', $message );
	}

	public function test_headroom_is_filterable() {
		Filters\expectApplied( 'codo_csp_header_buffer_headroom' )->once()->with( 1024, 4096 )->andReturn( 0 );
		$this->assertFalse( BufferLimit::check( 4096 )[0] );
	}
}
