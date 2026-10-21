<?php
/**
 * Tests for Settings constant overrides. Constants cannot be undefined, so
 * each test runs in its own process.
 *
 * @package CodoDigital\Csp\Tests
 */

namespace CodoDigital\Csp\Tests\Unit\Settings;

use CodoDigital\Csp\Settings\Settings;
use CodoDigital\Csp\Tests\TestCase;

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class SettingsConstantsTest extends TestCase {

	public function test_mode_constant_overrides_stored_mode() {
		define( 'CODO_CSP_MODE', 'enforce' );
		$this->options[ Settings::OPTION ] = array( 'mode' => Settings::MODE_REPORT_ONLY );
		$settings                          = new Settings();
		$this->assertTrue( $settings->is_enforcing() );
		$this->assertTrue( $settings->is_locked( 'mode' ) );
		$this->assertFalse( $settings->is_locked( 'reporting' ) );

		// Stored but has no effect while the constant is defined.
		$settings->update( array( 'mode' => Settings::MODE_REPORT_ONLY ) );
		$this->assertSame( Settings::MODE_REPORT_ONLY, $this->options[ Settings::OPTION ]['mode'] );
		$this->assertSame( Settings::MODE_ENFORCE, $settings->get( 'mode' ) );
	}

	public function test_invalid_mode_constant_is_ignored() {
		define( 'CODO_CSP_MODE', 'block-everything' );
		$settings = new Settings();
		$this->assertFalse( $settings->is_locked( 'mode' ) );
		$this->assertSame( Settings::MODE_REPORT_ONLY, $settings->get( 'mode' ) );
	}

	public function test_report_uri_constant_switches_to_external() {
		define( 'CODO_CSP_REPORT_URI', ' https://collector.example.com/r ' );
		$this->options[ Settings::OPTION ] = array(
			'reporting'    => Settings::REPORTING_BUILTIN,
			'report_until' => time() + 1000,
		);
		$settings                          = new Settings();
		$this->assertSame( Settings::REPORTING_EXTERNAL, $settings->get( 'reporting' ) );
		$this->assertSame( 'https://collector.example.com/r', $settings->get( 'external_uri' ) );
		$this->assertSame( 'https://collector.example.com/r', $settings->report_uri() );
		$this->assertFalse( $settings->is_collecting(), 'built-in endpoint turned off' );
		$this->assertTrue( $settings->is_locked( 'reporting' ) );
		$this->assertTrue( $settings->is_locked( 'external_uri' ) );
	}

	public function test_invalid_report_uri_constant_turns_reporting_off() {
		define( 'CODO_CSP_REPORT_URI', 'http://insecure.example.com/r' );
		$settings = new Settings();
		$this->assertSame( Settings::REPORTING_OFF, $settings->get( 'reporting' ) );
		$this->assertSame( '', $settings->get( 'external_uri' ) );
		$this->assertSame( '', $settings->report_uri() );
	}

	public function test_login_constant() {
		define( 'CODO_CSP_LOGIN', 0 );
		$this->options[ Settings::OPTION ] = array( 'login_enabled' => true );
		$settings                          = new Settings();
		$this->assertFalse( $settings->get( 'login_enabled' ) );
		$this->assertTrue( $settings->is_locked( 'login_enabled' ) );
		$this->assertSame( array( 'login_enabled' => false ), $settings->constants() );
	}

	public function test_disable_constant_true() {
		define( 'CODO_CSP_DISABLE', true );
		$this->assertTrue( ( new Settings() )->is_disabled() );
	}

	public function test_disable_constant_false() {
		define( 'CODO_CSP_DISABLE', false );
		$this->assertFalse( ( new Settings() )->is_disabled() );
	}
}
