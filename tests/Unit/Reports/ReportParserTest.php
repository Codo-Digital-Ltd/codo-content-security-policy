<?php
/**
 * Tests for ReportParser: both browser formats, reduction to safe shapes and noise filtering.
 *
 * @package CodoDigital\Csp\Tests
 */

namespace CodoDigital\Csp\Tests\Unit\Reports;

use CodoDigital\Csp\Reports\ReportParser;
use CodoDigital\Csp\Tests\TestCase;

class ReportParserTest extends TestCase {

	const HOME = 'https://www.example.com/';

	/**
	 * Parse with the test home URL.
	 *
	 * @param mixed $data Data to JSON-encode (strings are passed raw).
	 * @return array<int, array<string, string>>
	 */
	private function parse( $data ) {
		return ( new ReportParser() )->parse( is_string( $data ) ? $data : json_encode( $data ), self::HOME );
	}

	/**
	 * A report-uri style body.
	 *
	 * @param array<string, mixed> $fields Fields to override.
	 * @return array<string, mixed>
	 */
	private function legacy( array $fields = array() ) {
		return array(
			'csp-report' => array_merge(
				array(
					'document-uri'        => 'https://www.example.com/shop/?token=secret',
					'blocked-uri'         => 'https://cdn.example.net/lib/app.js?v=1',
					'effective-directive' => 'script-src-elem',
					'disposition'         => 'report',
					'script-sample'       => 'alert(1)',
				),
				$fields
			),
		);
	}

	/**
	 * A Reporting API item.
	 *
	 * @param array<string, mixed> $body Body fields to override.
	 * @return array<string, mixed>
	 */
	private function api_item( array $body = array() ) {
		return array(
			'type' => 'csp-violation',
			'url'  => 'https://www.example.com/fallback/',
			'body' => array_merge(
				array(
					'documentURL'        => 'https://www.example.com/about/?utm=1',
					'blockedURL'         => 'https://fonts.gstatic.com/s/font.woff2',
					'effectiveDirective' => 'font-src',
					'disposition'        => 'enforce',
				),
				$body
			),
		);
	}

	public function test_parses_report_uri_format() {
		$this->assertSame(
			array(
				array(
					'directive'   => 'script-src-elem',
					'blocked'     => 'https://cdn.example.net',
					'document'    => '/shop/',
					'disposition' => 'report',
				),
			),
			$this->parse( $this->legacy() )
		);
	}

	public function test_parses_reporting_api_format() {
		$this->assertSame(
			array(
				array(
					'directive'   => 'font-src',
					'blocked'     => 'https://fonts.gstatic.com',
					'document'    => '/about/',
					'disposition' => 'enforce',
				),
			),
			$this->parse( array( $this->api_item() ) )
		);
	}

	public function test_reporting_api_falls_back_to_item_url() {
		$item = $this->api_item();
		unset( $item['body']['documentURL'] );
		$reports = $this->parse( array( $item ) );
		$this->assertSame( '/fallback/', $reports[0]['document'] );
	}

	public function test_reporting_api_missing_fields_default_to_empty() {
		$item = array(
			'type' => 'csp-violation',
			'body' => array(
				'blockedURL'         => 'inline',
				'effectiveDirective' => 'style-src-attr',
			),
		);
		// No document URL at all: the empty document is not on this host.
		$this->assertSame( array(), $this->parse( array( $item ) ) );
	}

	public function test_violated_directive_fallback_takes_first_token() {
		$report = $this->legacy( array( 'violated-directive' => "Script-Src-Elem 'self'" ) );
		unset( $report['csp-report']['effective-directive'] );
		$this->assertSame( 'script-src-elem', $this->parse( $report )[0]['directive'] );
	}

	public function test_missing_directive_is_dropped() {
		$report = $this->legacy();
		unset( $report['csp-report']['effective-directive'] );
		$this->assertSame( array(), $this->parse( $report ) );
	}

	public function test_invalid_directive_is_dropped() {
		$this->assertSame( array(), $this->parse( $this->legacy( array( 'effective-directive' => 'script_src<x>' ) ) ) );
		$this->assertSame( array(), $this->parse( $this->legacy( array( 'effective-directive' => str_repeat( 'a', 41 ) ) ) ) );
	}

	/**
	 * @dataProvider blocked_values
	 */
	public function test_blocked_values_are_reduced( $raw, $expected ) {
		$reports = $this->parse( $this->legacy( array( 'blocked-uri' => $raw ) ) );
		if ( null === $expected ) {
			$this->assertSame( array(), $reports );
			return;
		}
		$this->assertSame( $expected, $reports[0]['blocked'] );
	}

	public function blocked_values() {
		return array(
			'inline keyword'          => array( 'inline', 'inline' ),
			'eval keyword upper'      => array( ' EVAL ', 'eval' ),
			'wasm-eval'               => array( 'wasm-eval', 'wasm-eval' ),
			'trusted types'           => array( 'trusted-types-sink', 'trusted-types-sink' ),
			'self keyword'            => array( 'self', 'self' ),
			'bare data'               => array( 'data', 'data:' ),
			'bare blob'               => array( 'BLOB', 'blob:' ),
			'data url'                => array( 'data:image/png;base64,AAAA', 'data:' ),
			'blob url'                => array( 'blob:https://www.example.com/uuid', 'blob:' ),
			'full url reduced'        => array( 'https://user:pw@cdn.example.net:8443/a/b.js?token=x#y', 'https://cdn.example.net:8443' ),
			'default port dropped'    => array( 'https://cdn.example.net:443/x', 'https://cdn.example.net' ),
			'wss origin'              => array( 'wss://live.example.net/socket', 'wss://live.example.net' ),
			'empty'                   => array( '', null ),
			'not a url'               => array( 'garbage', null ),
			'scheme without host'     => array( 'about:blank', null ),
			'host with bad chars'     => array( 'https://bad_host.example.net/x', null ),
			'over-long origin'        => array( 'https://' . str_repeat( 'a', 260 ) . '.com/', null ),
		);
	}

	public function test_other_host_documents_are_dropped() {
		$this->assertSame( array(), $this->parse( $this->legacy( array( 'document-uri' => 'https://evil.example.org/' ) ) ) );
	}

	public function test_unparseable_document_is_dropped() {
		$this->assertSame( array(), $this->parse( $this->legacy( array( 'document-uri' => '/relative' ) ) ) );
	}

	public function test_bad_home_url_drops_everything() {
		$this->assertSame( array(), ( new ReportParser() )->parse( json_encode( $this->legacy() ), 'not a url' ) );
	}

	public function test_document_without_path_becomes_slash() {
		$reports = $this->parse( $this->legacy( array( 'document-uri' => 'https://www.example.com?x=1' ) ) );
		$this->assertSame( '/', $reports[0]['document'] );
	}

	public function test_document_path_is_truncated() {
		$long    = '/' . str_repeat( 'p', 300 );
		$reports = $this->parse( $this->legacy( array( 'document-uri' => 'https://www.example.com' . $long ) ) );
		$this->assertSame( 255, strlen( $reports[0]['document'] ) );
	}

	/**
	 * @dataProvider extension_reports
	 */
	public function test_extension_noise_is_dropped( $blocked, $source_file ) {
		$fields = array( 'blocked-uri' => $blocked );
		if ( null !== $source_file ) {
			$fields['source-file'] = $source_file;
		}
		$this->assertSame( array(), $this->parse( $this->legacy( $fields ) ) );
	}

	public function extension_reports() {
		return array(
			'chrome blocked'         => array( 'chrome-extension://abc/x.js', null ),
			'moz blocked'            => array( 'MOZ-EXTENSION://abc/x.js', null ),
			'safari-web blocked'     => array( 'safari-web-extension://abc/x.js', null ),
			'chrome source file'     => array( 'inline', 'chrome-extension://abc/content.js' ),
			'moz source file'        => array( 'eval', 'moz-extension://abc/content.js' ),
			'ms-browser source file' => array( 'inline', 'ms-browser-extension://abc/content.js' ),
		);
	}

	public function test_extension_source_file_in_reporting_api_is_dropped() {
		$this->assertSame( array(), $this->parse( array( $this->api_item( array( 'sourceFile' => 'chrome-extension://abc/x.js' ) ) ) ) );
	}

	public function test_non_string_fields_drop_the_report() {
		$this->assertSame( array(), $this->parse( $this->legacy( array( 'blocked-uri' => array( 'x' ) ) ) ) );
		$this->assertSame( array(), $this->parse( $this->legacy( array( 'disposition' => 1 ) ) ) );
		$this->assertSame( array(), $this->parse( array( $this->api_item( array( 'documentURL' => 5 ) ) ) ) );
	}

	/**
	 * @dataProvider dispositions
	 */
	public function test_disposition_is_normalised( $raw, $expected ) {
		$this->assertSame( $expected, $this->parse( $this->legacy( array( 'disposition' => $raw ) ) )[0]['disposition'] );
	}

	public function dispositions() {
		return array(
			'enforce'      => array( 'enforce', 'enforce' ),
			'report upper' => array( 'REPORT', 'report' ),
			'unknown'      => array( 'block', '' ),
			'empty'        => array( '', '' ),
		);
	}

	public function test_missing_legacy_fields_default_to_empty() {
		$body = array(
			'csp-report' => array(
				'document-uri'        => 'https://www.example.com/',
				'blocked-uri'         => 'inline',
				'effective-directive' => 'script-src-attr',
			),
		);
		$this->assertSame(
			array(
				array(
					'directive'   => 'script-src-attr',
					'blocked'     => 'inline',
					'document'    => '/',
					'disposition' => '',
				),
			),
			$this->parse( $body )
		);
	}

	/**
	 * @dataProvider unusable_bodies
	 */
	public function test_unusable_bodies_give_nothing( $body ) {
		$this->assertSame( array(), $this->parse( $body ) );
	}

	public function unusable_bodies() {
		return array(
			'invalid json'          => array( '{"csp-report":' ),
			'empty string'          => array( '' ),
			'scalar json'           => array( '42' ),
			'csp-report not array'  => array( array( 'csp-report' => 'x' ) ),
			'assoc without report'  => array( array( 'foo' => array( 'bar' ) ) ),
			'empty list'            => array( array() ),
			'non-csp type'          => array( array( array( 'type' => 'deprecation', 'body' => array( 'id' => 'x' ) ) ) ),
			'item not array'        => array( array( 'csp-violation' ) ),
			'item without body'     => array( array( array( 'type' => 'csp-violation' ) ) ),
			'body not array'        => array( array( array( 'type' => 'csp-violation', 'body' => 'x' ) ) ),
		);
	}

	public function test_mixed_reporting_api_batch_keeps_valid_items() {
		$reports = $this->parse(
			array(
				array( 'type' => 'intervention', 'body' => array() ),
				$this->api_item(),
				$this->api_item( array( 'blockedURL' => 'eval', 'effectiveDirective' => 'script-src' ) ),
			)
		);
		$this->assertCount( 2, $reports );
		$this->assertSame( 'eval', $reports[1]['blocked'] );
		$this->assertSame( 'script-src', $reports[1]['directive'] );
	}

	public function test_reporting_api_is_capped() {
		$items = array_fill( 0, ReportParser::MAX_REPORTS + 10, $this->api_item() );
		$this->assertCount( ReportParser::MAX_REPORTS, $this->parse( $items ) );
	}

	public function test_cap_counts_skipped_items() {
		// Only the first MAX_REPORTS items are looked at, valid or not.
		$items   = array_fill( 0, ReportParser::MAX_REPORTS, array( 'type' => 'deprecation', 'body' => array() ) );
		$items[] = $this->api_item();
		$this->assertSame( array(), $this->parse( $items ) );
	}
}
