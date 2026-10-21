<?php
/**
 * Receives violation reports from browsers.
 *
 * @package CodoDigital\Csp
 */

namespace CodoDigital\Csp\Reports;

use CodoDigital\Csp\Settings\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * The built-in report collector, at /?codo_csp_report=<token>.
 *
 * Built for slow sites: it answers on plugins_loaded, before the theme loads
 * and init runs, always with 204 and no body, and does as little as possible:
 *
 * - nothing is read unless the collection window is open and the token matches
 *   (the token is in every page's headers, so it only filters out stray traffic);
 * - a per-minute rate limit sheds load before the body is parsed;
 * - bodies over 64 KB are ignored, and at most 50 reports per request are used;
 * - reports are aggregated (one row per unique violation, capped).
 *
 * Chromium batches reports through the Reporting API (Reporting-Endpoints),
 * so one page view usually costs one request, not one per violation.
 */
class ReportEndpoint {

	const QUERY_VAR = 'codo_csp_report';
	const MAX_BYTES = 65536;

	/**
	 * Settings.
	 *
	 * @var Settings
	 */
	private $settings;

	/**
	 * Parser.
	 *
	 * @var ReportParser
	 */
	private $parser;

	/**
	 * Storage.
	 *
	 * @var ReportRepository
	 */
	private $repository;

	/**
	 * Rate limiter.
	 *
	 * @var RateLimiter
	 */
	private $limiter;

	/**
	 * Reads the request body.
	 *
	 * @var callable
	 */
	private $reader;

	/**
	 * Ends the request.
	 *
	 * @var callable
	 */
	private $terminate;

	/**
	 * Constructor.
	 *
	 * @param Settings         $settings   Settings.
	 * @param ReportParser     $parser     Parser.
	 * @param ReportRepository $repository Storage.
	 * @param RateLimiter      $limiter    Rate limiter.
	 * @param callable|null    $reader     Body reader (tests).
	 * @param callable|null    $terminate  Called to end the request (tests).
	 */
	public function __construct( Settings $settings, ReportParser $parser, ReportRepository $repository, RateLimiter $limiter, $reader = null, $terminate = null ) {
		$this->settings   = $settings;
		$this->parser     = $parser;
		$this->repository = $repository;
		$this->limiter    = $limiter;
		$this->reader     = null !== $reader ? $reader : array( __CLASS__, 'read_body' );
		$this->terminate  = null !== $terminate ? $terminate : array( __CLASS__, 'exit_request' );
	}

	/**
	 * Read at most MAX_BYTES + 1 bytes of the body.
	 *
	 * @codeCoverageIgnore
	 * @return string
	 */
	public static function read_body() {
		$body = file_get_contents( 'php://input', false, null, 0, self::MAX_BYTES + 1 );
		return false === $body ? '' : $body;
	}

	/**
	 * Default terminator.
	 *
	 * @codeCoverageIgnore
	 * @return void
	 */
	public static function exit_request() {
		exit;
	}

	/**
	 * Handle the request if it is a report; otherwise do nothing.
	 *
	 * @return void
	 */
	public function maybe_handle() {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Browsers post reports anonymously; the collection window, rate limit and row cap bound it.
		if ( ! isset( $_GET[ self::QUERY_VAR ] ) ) {
			return;
		}
		$token   = sanitize_text_field( wp_unslash( $_GET[ self::QUERY_VAR ] ) );
		$context = isset( $_GET['ctx'] ) && 'login' === $_GET['ctx'] ? 'login' : 'site';
		// phpcs:enable

		$this->process( $token, $context );

		if ( ! headers_sent() ) {
			status_header( 204 );
			nocache_headers();
		}
		call_user_func( $this->terminate );
	}

	/**
	 * Check and store the reports in this request.
	 *
	 * @param string $token   Token from the URL.
	 * @param string $context site or login (which policy the reports are about).
	 * @return int Reports stored.
	 */
	public function process( $token, $context = 'site' ) {
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : '';
		if ( 'POST' !== $method || ! $this->settings->is_collecting() ) {
			return 0;
		}
		$expected = (string) $this->settings->get( 'report_token' );
		if ( '' === $expected || ! hash_equals( $expected, (string) $token ) ) {
			return 0;
		}
		if ( ! $this->limiter->allow() ) {
			return 0;
		}

		$body = (string) call_user_func( $this->reader );
		if ( '' === $body || strlen( $body ) > self::MAX_BYTES ) {
			return 0;
		}

		$this->repository->maybe_install();
		$stored = 0;
		foreach ( $this->parser->parse( $body, home_url( '/' ) ) as $report ) {
			$report['context'] = 'login' === $context ? 'login' : 'site';
			if ( $this->repository->record( $report ) ) {
				++$stored;
			}
		}
		return $stored;
	}
}
