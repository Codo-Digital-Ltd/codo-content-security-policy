<?php
/**
 * Tests for Settings: defaults, sanitising, URIs and the report collector.
 *
 * @package CodoDigital\Csp\Tests
 */

namespace CodoDigital\Csp\Tests\Unit\Settings;

use Brain\Monkey\Functions;
use CodoDigital\Csp\Settings\Settings;
use CodoDigital\Csp\Tests\TestCase;

class SettingsTest extends TestCase {

	const NOW = 1700000000;

	public function test_defaults_when_nothing_stored() {
		$settings = new Settings();
		$this->assertSame( Settings::defaults(), $settings->all() );
		$this->assertSame( Settings::MODE_REPORT_ONLY, $settings->get( 'mode' ) );
		$this->assertFalse( $settings->is_enforcing() );
		$this->assertFalse( $settings->is_disabled() );
		$this->assertSame( array(), $settings->constants() );
		$this->assertFalse( $settings->is_locked( 'mode' ) );
	}

	public function test_get_unknown_key_is_null() {
		$this->assertNull( ( new Settings() )->get( 'nope' ) );
	}

	public function test_stored_values_merge_over_defaults_and_unknown_keys_are_dropped() {
		$this->options[ Settings::OPTION ] = array(
			'mode'  => Settings::MODE_ENFORCE,
			'bogus' => 'x',
		);
		$settings                          = new Settings();
		$all                               = $settings->all();
		$this->assertSame( Settings::MODE_ENFORCE, $all['mode'] );
		$this->assertArrayNotHasKey( 'bogus', $all );
		$this->assertTrue( $all['purge_caches'] );
		$this->assertTrue( $settings->is_enforcing() );
	}

	public function test_corrupt_option_falls_back_to_defaults() {
		$this->options[ Settings::OPTION ] = 'garbage';
		$this->assertSame( Settings::defaults(), ( new Settings() )->all() );
	}

	public function test_values_are_cached_until_flushed() {
		$settings = new Settings();
		$this->assertSame( Settings::MODE_REPORT_ONLY, $settings->get( 'mode' ) );

		$this->options[ Settings::OPTION ] = array( 'mode' => Settings::MODE_ENFORCE );
		$this->assertSame( Settings::MODE_REPORT_ONLY, $settings->get( 'mode' ), 'cached' );

		$settings->flush();
		$this->assertSame( Settings::MODE_ENFORCE, $settings->get( 'mode' ) );
	}

	public function test_update_ignores_unknown_keys_and_keeps_existing_values() {
		$this->options[ Settings::OPTION ] = array(
			'mode'  => Settings::MODE_ENFORCE,
			'stray' => 1,
		);
		$settings                          = new Settings();
		$settings->update(
			array(
				'skip_builders' => 0,
				'unknown'       => 'x',
			)
		);
		$stored = $this->options[ Settings::OPTION ];
		$this->assertArrayNotHasKey( 'unknown', $stored );
		$this->assertArrayNotHasKey( 'stray', $stored );
		$this->assertSame( Settings::MODE_ENFORCE, $stored['mode'] );
		$this->assertFalse( $stored['skip_builders'] );
		$this->assertFalse( $settings->get( 'skip_builders' ), 'cache refreshed' );
	}

	public function test_update_on_corrupt_option() {
		$this->options[ Settings::OPTION ] = 'garbage';
		( new Settings() )->update( array( 'mode' => Settings::MODE_ENFORCE ) );
		$this->assertSame( Settings::MODE_ENFORCE, $this->options[ Settings::OPTION ]['mode'] );
		$this->assertSame( Settings::REPORTING_BUILTIN, $this->options[ Settings::OPTION ]['reporting'] );
	}

	/**
	 * @dataProvider sanitised_values
	 */
	public function test_update_sanitises( $key, $value, $expected ) {
		$settings = new Settings();
		$settings->update( array( $key => $value ) );
		$this->assertSame( $expected, $settings->get( $key ) );
		$this->assertSame( $expected, $this->options[ Settings::OPTION ][ $key ] );
	}

	public function sanitised_values() {
		return array(
			'mode enforce'           => array( 'mode', 'enforce', Settings::MODE_ENFORCE ),
			'mode report-only'       => array( 'mode', 'report-only', Settings::MODE_REPORT_ONLY ),
			'mode junk'              => array( 'mode', 'ENFORCE', Settings::MODE_REPORT_ONLY ),
			'reporting builtin'      => array( 'reporting', 'builtin', Settings::REPORTING_BUILTIN ),
			'reporting external'     => array( 'reporting', 'external', Settings::REPORTING_EXTERNAL ),
			'reporting off'          => array( 'reporting', 'off', Settings::REPORTING_OFF ),
			'reporting junk'         => array( 'reporting', 'everywhere', Settings::REPORTING_OFF ),
			'report_until int'       => array( 'report_until', '123', 123 ),
			'report_until negative'  => array( 'report_until', -5, 0 ),
			'external_uri valid'     => array( 'external_uri', ' https://r.example.com/csp ', 'https://r.example.com/csp' ),
			'external_uri invalid'   => array( 'external_uri', 'http://r.example.com', '' ),
			'report_token stripped'  => array( 'report_token', "ab-c\r\n12!", 'abc12' ),
			'bool true'              => array( 'login_enabled', '1', true ),
			'bool false'             => array( 'upgrade_insecure', '', false ),
			'bool scan_on_save'      => array( 'scan_on_save', 0, false ),
			'bool purge_caches true' => array( 'purge_caches', 'yes', true ),
		);
	}

	/**
	 * @dataProvider uris
	 */
	public function test_sanitize_uri( $uri, $expected ) {
		$this->assertSame( $expected, Settings::sanitize_uri( $uri ) );
	}

	public function uris() {
		return array(
			'https'                => array( 'https://report.example.com/csp?x=1', 'https://report.example.com/csp?x=1' ),
			'https upper scheme'   => array( 'HTTPS://report.example.com', 'HTTPS://report.example.com' ),
			'trimmed'              => array( "  https://a.example.com\n", 'https://a.example.com' ),
			'empty'                => array( '', '' ),
			'whitespace only'      => array( '   ', '' ),
			'http remote'          => array( 'http://report.example.com', '' ),
			'http localhost'       => array( 'http://localhost:8080/csp', 'http://localhost:8080/csp' ),
			'http loopback'        => array( 'http://127.0.0.1/csp', 'http://127.0.0.1/csp' ),
			'ftp'                  => array( 'ftp://example.com', '' ),
			'relative'             => array( '/csp-report', '' ),
			'no scheme'            => array( '//example.com/csp', '' ),
			'mailto has no host'   => array( 'mailto:a@example.com', '' ),
			'unparseable'          => array( 'https://', '' ),
			'semicolon'            => array( 'https://example.com/a;script-src *', '' ),
			'comma'                => array( 'https://example.com/a,b', '' ),
			'quote'                => array( 'https://example.com/"x', '' ),
			'single quote'         => array( "https://example.com/'x", '' ),
			'angle bracket'        => array( 'https://example.com/<x>', '' ),
			'inner space'          => array( 'https://example.com/a b', '' ),
			'header injection'     => array( "https://example.com/\r\nSet-Cookie: x", '' ),
			'control char'         => array( "https://example.com/\x01", '' ),
			'delete char'          => array( "https://example.com/\x7f", '' ),
		);
	}

	public function test_report_token_is_generated_once() {
		Functions\expect( 'wp_generate_password' )->once()->with( 20, false, false )->andReturn( 'AbC123xyz' );
		$settings = new Settings();
		$this->assertSame( 'AbC123xyz', $settings->report_token() );
		$this->assertSame( 'AbC123xyz', $settings->report_token() );
		$this->assertSame( 'AbC123xyz', $this->options[ Settings::OPTION ]['report_token'] );
	}

	public function test_report_token_existing_is_reused() {
		Functions\expect( 'wp_generate_password' )->never();
		$this->options[ Settings::OPTION ] = array( 'report_token' => 'stored' );
		$this->assertSame( 'stored', ( new Settings() )->report_token() );
	}

	public function test_report_token_is_sanitised_when_generated() {
		Functions\when( 'wp_generate_password' )->justReturn( 'a-b c' );
		$this->assertSame( 'abc', ( new Settings() )->report_token() );
	}

	public function test_collect_for_allowed_window() {
		$settings = new Settings();
		$settings->collect_for( 30, self::NOW );
		$this->assertSame( Settings::REPORTING_BUILTIN, $settings->get( 'reporting' ) );
		$this->assertSame( self::NOW + 30 * DAY_IN_SECONDS, $settings->get( 'report_until' ) );
		$this->assertTrue( $settings->is_collecting( self::NOW ) );
		$this->assertTrue( $settings->is_collecting( self::NOW + 30 * DAY_IN_SECONDS - 1 ) );
		$this->assertFalse( $settings->is_collecting( self::NOW + 30 * DAY_IN_SECONDS ) );
	}

	public function test_collect_for_odd_window_falls_back_to_seven_days() {
		$this->options[ Settings::OPTION ] = array( 'reporting' => Settings::REPORTING_OFF );
		$settings                          = new Settings();
		$settings->collect_for( 365, self::NOW );
		$this->assertSame( Settings::REPORTING_BUILTIN, $settings->get( 'reporting' ) );
		$this->assertSame( self::NOW + 7 * DAY_IN_SECONDS, $settings->get( 'report_until' ) );
	}

	public function test_collect_for_defaults_to_now() {
		$settings = new Settings();
		$before   = time();
		$settings->collect_for( 1 );
		$until = $settings->get( 'report_until' );
		$this->assertGreaterThanOrEqual( $before + DAY_IN_SECONDS, $until );
		$this->assertLessThanOrEqual( time() + DAY_IN_SECONDS, $until );
		$this->assertTrue( $settings->is_collecting() );
	}

	public function test_stop_collecting() {
		$settings = new Settings();
		$settings->collect_for( 7, self::NOW );
		$settings->stop_collecting();
		$this->assertSame( 0, $settings->get( 'report_until' ) );
		$this->assertFalse( $settings->is_collecting( self::NOW ) );
		$this->assertSame( '', $settings->report_uri( self::NOW ) );
	}

	public function test_not_collecting_when_reporting_is_not_builtin() {
		$this->options[ Settings::OPTION ] = array(
			'reporting'    => Settings::REPORTING_OFF,
			'report_until' => self::NOW + 100,
		);
		$settings                          = new Settings();
		$this->assertFalse( $settings->is_collecting( self::NOW ) );
		$this->assertSame( '', $settings->report_uri( self::NOW ) );
	}

	public function test_report_uri_builtin_while_collecting() {
		$this->options[ Settings::OPTION ] = array(
			'report_until' => self::NOW + 100,
			'report_token' => 'tok123',
		);
		$this->assertSame( 'https://www.example.com/?codo_csp_report=tok123', ( new Settings() )->report_uri( self::NOW ) );
	}

	public function test_report_uri_marks_login_reports() {
		$this->options[ Settings::OPTION ] = array(
			'report_until' => self::NOW + 100,
			'report_token' => 'tok123',
		);
		$settings = new Settings();
		$this->assertSame( 'https://www.example.com/?codo_csp_report=tok123&ctx=login', $settings->report_uri( self::NOW, 'login' ) );
		$this->assertSame( 'https://www.example.com/?codo_csp_report=tok123', $settings->report_uri( self::NOW, 'site' ) );
	}

	public function test_report_uri_external_is_the_same_for_login() {
		$this->options[ Settings::OPTION ] = array(
			'reporting'    => Settings::REPORTING_EXTERNAL,
			'external_uri' => 'https://collector.example.com/r',
		);
		$this->assertSame( 'https://collector.example.com/r', ( new Settings() )->report_uri( self::NOW, 'login' ) );
	}

	public function test_report_uri_builtin_after_window_is_empty() {
		$this->options[ Settings::OPTION ] = array(
			'report_until' => self::NOW,
			'report_token' => 'tok123',
		);
		$this->assertSame( '', ( new Settings() )->report_uri( self::NOW ) );
	}

	public function test_report_uri_external_ignores_window() {
		$this->options[ Settings::OPTION ] = array(
			'reporting'    => Settings::REPORTING_EXTERNAL,
			'external_uri' => 'https://collector.example.com/r',
			'report_until' => 0,
		);
		$this->assertSame( 'https://collector.example.com/r', ( new Settings() )->report_uri( self::NOW ) );
	}

	public function test_report_uri_external_without_uri_is_empty() {
		$this->options[ Settings::OPTION ] = array( 'reporting' => Settings::REPORTING_EXTERNAL );
		$this->assertSame( '', ( new Settings() )->report_uri() );
	}
}
