<?php
/**
 * Tests for ReportEndpoint: gating, limits and storage.
 *
 * @package CodoDigital\Csp\Tests
 */

namespace CodoDigital\Csp\Tests\Unit\Reports;

use Brain\Monkey\Functions;
use CodoDigital\Csp\Reports\RateLimiter;
use CodoDigital\Csp\Reports\ReportEndpoint;
use CodoDigital\Csp\Reports\ReportParser;
use CodoDigital\Csp\Reports\ReportRepository;
use CodoDigital\Csp\Settings\Settings;
use CodoDigital\Csp\Tests\TestCase;

class ReportEndpointTest extends TestCase {

	const TOKEN = 'abc123TOKEN';

	/** @var \Mockery\MockInterface */
	private $repository;

	/** @var \Mockery\MockInterface */
	private $limiter;

	/** @var string Body returned by the reader. */
	private $body = '';

	/** @var int Times the reader was called. */
	private $reads = 0;

	/** @var int Times the terminator was called. */
	private $terminated = 0;

	/** @var array<string, mixed> Saved superglobals. */
	private $saved_get;

	/** @var array<string, mixed> Saved superglobals. */
	private $saved_server;

	protected function setUp(): void {
		parent::setUp();
		$this->saved_get    = $_GET;
		$this->saved_server = $_SERVER;
		$_GET               = array();
		unset( $_SERVER['REQUEST_METHOD'] );

		$this->body       = '';
		$this->reads      = 0;
		$this->terminated = 0;
		$this->repository = \Mockery::mock( ReportRepository::class );
		$this->limiter    = \Mockery::mock( RateLimiter::class );

		$this->options[ Settings::OPTION ] = array(
			'reporting'    => Settings::REPORTING_BUILTIN,
			'report_until' => time() + 3600,
			'report_token' => self::TOKEN,
		);
	}

	protected function tearDown(): void {
		$_GET    = $this->saved_get;
		$_SERVER = $this->saved_server;
		parent::tearDown();
	}

	private function endpoint() {
		return new ReportEndpoint(
			new Settings(),
			new ReportParser(),
			$this->repository,
			$this->limiter,
			function () {
				++$this->reads;
				return $this->body;
			},
			function () {
				++$this->terminated;
			}
		);
	}

	private function report_body( $count ) {
		$items = array();
		for ( $i = 0; $i < $count; $i++ ) {
			$items[] = array(
				'type' => 'csp-violation',
				'url'  => 'https://www.example.com/page-' . $i . '/',
				'body' => array(
					'documentURL'        => 'https://www.example.com/page-' . $i . '/',
					'blockedURL'         => 'https://cdn.example.net/x.js',
					'effectiveDirective' => 'script-src-elem',
					'disposition'        => 'report',
				),
			);
		}
		return json_encode( $items );
	}

	public function test_default_callables_are_used_when_none_given() {
		$endpoint = new ReportEndpoint( new Settings(), new ReportParser(), $this->repository, $this->limiter );
		// Not a POST, so neither the default reader nor terminator runs.
		$this->assertSame( 0, $endpoint->process( self::TOKEN ) );
	}

	public function test_maybe_handle_ignores_other_requests() {
		Functions\expect( 'status_header' )->never();
		$this->limiter->shouldNotReceive( 'allow' );
		$this->endpoint()->maybe_handle();
		$this->assertSame( 0, $this->terminated );
	}

	public function test_maybe_handle_answers_204_and_terminates() {
		$_GET[ ReportEndpoint::QUERY_VAR ] = self::TOKEN;
		$_SERVER['REQUEST_METHOD']         = 'post';
		$this->body                        = $this->report_body( 1 );
		$this->limiter->shouldReceive( 'allow' )->once()->andReturn( true );
		$this->repository->shouldReceive( 'maybe_install' )->once();
		$this->repository->shouldReceive( 'record' )->once()->andReturn( true );
		Functions\when( 'CodoDigital\Csp\Reports\headers_sent' )->justReturn( false );
		Functions\expect( 'status_header' )->once()->with( 204 );
		Functions\expect( 'nocache_headers' )->once();

		$this->endpoint()->maybe_handle();
		$this->assertSame( 1, $this->terminated );
	}

	public function test_maybe_handle_skips_headers_once_sent() {
		$_GET[ ReportEndpoint::QUERY_VAR ] = 'wrong';
		Functions\when( 'CodoDigital\Csp\Reports\headers_sent' )->justReturn( true );
		Functions\expect( 'status_header' )->never();
		Functions\expect( 'nocache_headers' )->never();

		$this->endpoint()->maybe_handle();
		$this->assertSame( 1, $this->terminated );
	}

	/**
	 * @dataProvider non_post_methods
	 */
	public function test_only_post_is_processed( $method ) {
		if ( null !== $method ) {
			$_SERVER['REQUEST_METHOD'] = $method;
		}
		$this->limiter->shouldNotReceive( 'allow' );
		$this->assertSame( 0, $this->endpoint()->process( self::TOKEN ) );
		$this->assertSame( 0, $this->reads );
	}

	public function non_post_methods() {
		return array(
			'missing' => array( null ),
			'get'     => array( 'GET' ),
			'options' => array( 'OPTIONS' ),
		);
	}

	public function test_nothing_when_not_collecting() {
		$_SERVER['REQUEST_METHOD']                         = 'POST';
		$this->options[ Settings::OPTION ]['report_until'] = time() - 1;
		$this->limiter->shouldNotReceive( 'allow' );
		$this->assertSame( 0, $this->endpoint()->process( self::TOKEN ) );
	}

	public function test_nothing_when_reporting_is_external() {
		$_SERVER['REQUEST_METHOD']                      = 'POST';
		$this->options[ Settings::OPTION ]['reporting'] = Settings::REPORTING_EXTERNAL;
		$this->limiter->shouldNotReceive( 'allow' );
		$this->assertSame( 0, $this->endpoint()->process( self::TOKEN ) );
	}

	public function test_empty_stored_token_refuses() {
		$_SERVER['REQUEST_METHOD']                         = 'POST';
		$this->options[ Settings::OPTION ]['report_token'] = '';
		$this->limiter->shouldNotReceive( 'allow' );
		$this->assertSame( 0, $this->endpoint()->process( '' ) );
	}

	/**
	 * @dataProvider wrong_tokens
	 */
	public function test_mismatched_token_refuses( $token ) {
		$_SERVER['REQUEST_METHOD'] = 'POST';
		$this->limiter->shouldNotReceive( 'allow' );
		$this->assertSame( 0, $this->endpoint()->process( $token ) );
		$this->assertSame( 0, $this->reads );
	}

	public function wrong_tokens() {
		return array(
			'empty'      => array( '' ),
			'other'      => array( 'nope' ),
			'prefix'     => array( 'abc123' ),
			'case'       => array( strtolower( self::TOKEN ) ),
			'null'       => array( null ),
		);
	}

	public function test_rate_limited_requests_are_not_read() {
		$_SERVER['REQUEST_METHOD'] = 'POST';
		$this->limiter->shouldReceive( 'allow' )->once()->andReturn( false );
		$this->repository->shouldNotReceive( 'maybe_install' );
		$this->assertSame( 0, $this->endpoint()->process( self::TOKEN ) );
		$this->assertSame( 0, $this->reads );
	}

	public function test_empty_body_is_ignored() {
		$_SERVER['REQUEST_METHOD'] = 'POST';
		$this->limiter->shouldReceive( 'allow' )->andReturn( true );
		$this->repository->shouldNotReceive( 'maybe_install' );
		$this->assertSame( 0, $this->endpoint()->process( self::TOKEN ) );
		$this->assertSame( 1, $this->reads );
	}

	public function test_oversized_body_is_ignored() {
		$_SERVER['REQUEST_METHOD'] = 'POST';
		$this->body                = str_repeat( 'x', ReportEndpoint::MAX_BYTES + 1 );
		$this->limiter->shouldReceive( 'allow' )->andReturn( true );
		$this->repository->shouldNotReceive( 'maybe_install' );
		$this->assertSame( 0, $this->endpoint()->process( self::TOKEN ) );
	}

	public function test_body_at_limit_is_accepted() {
		$_SERVER['REQUEST_METHOD'] = 'POST';
		$this->body                = str_pad( $this->report_body( 1 ), ReportEndpoint::MAX_BYTES, ' ' );
		$this->limiter->shouldReceive( 'allow' )->andReturn( true );
		$this->repository->shouldReceive( 'maybe_install' )->once();
		$this->repository->shouldReceive( 'record' )->once()->andReturn( true );
		$this->assertSame( 1, $this->endpoint()->process( self::TOKEN ) );
	}

	public function test_stores_each_report_and_counts_successes() {
		$_SERVER['REQUEST_METHOD'] = 'POST';
		$this->body                = $this->report_body( 3 );
		$this->limiter->shouldReceive( 'allow' )->once()->andReturn( true );
		$this->repository->shouldReceive( 'maybe_install' )->once();
		$this->repository->shouldReceive( 'record' )->times( 3 )->with(
			\Mockery::on(
				static function ( $report ) {
					return 'script-src-elem' === $report['directive'] && 'https://cdn.example.net' === $report['blocked'];
				}
			)
		)->andReturn( true, false, true );

		$this->assertSame( 2, $this->endpoint()->process( self::TOKEN ) );
	}

	/**
	 * Expect one report recorded with a context.
	 *
	 * @param string $context Context.
	 * @return void
	 */
	private function expect_context( $context ) {
		$_SERVER['REQUEST_METHOD'] = 'POST';
		$this->body                = $this->report_body( 1 );
		$this->limiter->shouldReceive( 'allow' )->once()->andReturn( true );
		$this->repository->shouldReceive( 'maybe_install' )->once();
		$this->repository->shouldReceive( 'record' )->once()->with(
			\Mockery::on(
				static function ( $report ) use ( $context ) {
					return $context === $report['context'] && 'script-src-elem' === $report['directive'];
				}
			)
		)->andReturn( true );
	}

	/**
	 * @return array<string, array{0: mixed, 1: string}>
	 */
	public function process_contexts() {
		return array(
			'login'   => array( 'login', 'login' ),
			'site'    => array( 'site', 'site' ),
			'unknown' => array( 'admin', 'site' ),
		);
	}

	/**
	 * @dataProvider process_contexts
	 */
	public function test_process_records_the_context( $given, $stored ) {
		$this->expect_context( $stored );
		$this->assertSame( 1, $this->endpoint()->process( self::TOKEN, $given ) );
	}

	public function test_process_defaults_to_the_site_context() {
		$this->expect_context( 'site' );
		$this->assertSame( 1, $this->endpoint()->process( self::TOKEN ) );
	}

	/**
	 * @return array<string, array{0: array<string, mixed>, 1: string}>
	 */
	public function query_contexts() {
		return array(
			'login'   => array( array( 'ctx' => 'login' ), 'login' ),
			'missing' => array( array(), 'site' ),
			'other'   => array( array( 'ctx' => 'LOGIN' ), 'site' ),
			'array'   => array( array( 'ctx' => array( 'login' ) ), 'site' ),
		);
	}

	/**
	 * @dataProvider query_contexts
	 */
	public function test_maybe_handle_reads_the_context_from_the_url( array $get, $stored ) {
		$_GET                              = $get;
		$_GET[ ReportEndpoint::QUERY_VAR ] = self::TOKEN;
		$this->expect_context( $stored );
		Functions\when( 'CodoDigital\Csp\Reports\headers_sent' )->justReturn( true );

		$this->endpoint()->maybe_handle();
		$this->assertSame( 1, $this->terminated );
	}

	public function test_unparseable_body_stores_nothing() {
		$_SERVER['REQUEST_METHOD'] = 'POST';
		$this->body                = '{not json';
		$this->limiter->shouldReceive( 'allow' )->andReturn( true );
		$this->repository->shouldReceive( 'maybe_install' )->once();
		$this->repository->shouldNotReceive( 'record' );
		$this->assertSame( 0, $this->endpoint()->process( self::TOKEN ) );
	}
}
