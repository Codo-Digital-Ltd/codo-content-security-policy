<?php
/**
 * Tests for Presets: the preset catalogue, default policies and rule expansion.
 *
 * @package CodoDigital\Csp\Tests
 */

namespace CodoDigital\Csp\Tests\Unit\Policy;

use Brain\Monkey\Filters;
use CodoDigital\Csp\Policy\Directives;
use CodoDigital\Csp\Policy\Presets;
use CodoDigital\Csp\Policy\Source;
use CodoDigital\Csp\Tests\TestCase;

class PresetsTest extends TestCase {

	public function test_presets_have_labels_and_valid_rules() {
		$presets = Presets::all();
		$this->assertArrayHasKey( 'google-analytics', $presets );
		$this->assertArrayHasKey( 'stripe', $presets );
		foreach ( $presets as $id => $preset ) {
			$this->assertIsString( $preset['label'], $id );
			$this->assertNotSame( '', $preset['label'], $id );
			$this->assertNotEmpty( $preset['rules'], $id );
			foreach ( $preset['rules'] as $directive => $sources ) {
				$this->assertTrue( Directives::is_known( $directive ), "$id: $directive" );
				foreach ( $sources as $source ) {
					// Every bundled source is already in normal form.
					$this->assertSame( $source, Source::normalise( $directive, $source ), "$id: $source" );
				}
			}
		}
	}

	public function test_presets_filter_can_add() {
		Filters\expectApplied( 'codo_csp_presets' )->once()->andReturnUsing(
			static function ( $presets ) {
				$presets['custom'] = array(
					'label' => 'Custom',
					'rules' => array( 'img-src' => array( 'https://img.example.com' ) ),
				);
				return $presets;
			}
		);
		$this->assertArrayHasKey( 'custom', Presets::all() );
	}

	public function test_presets_filter_returning_non_array_is_ignored() {
		Filters\expectApplied( 'codo_csp_presets' )->once()->andReturn( 'broken' );
		$presets = Presets::all();
		$this->assertIsArray( $presets );
		$this->assertArrayHasKey( 'youtube', $presets );
	}

	public function test_site_defaults() {
		$rules = Presets::defaults( 'site' );
		$this->assertSame( array( "'self'" ), $rules['default-src'] );
		$this->assertSame( array( "'self'", "'unsafe-inline'" ), $rules['script-src'] );
		$this->assertSame( array( "'none'" ), $rules['object-src'] );
		$this->assertSame( array( "'self'" ), $rules['frame-src'] );
		$this->assertSame( array( "'self'" ), $rules['frame-ancestors'] );
		$this->assertSame( array( "'self'", 'blob:' ), $rules['worker-src'], "core's emoji loader starts a worker from a blob" );
		foreach ( $rules as $directive => $sources ) {
			$this->assertTrue( Directives::is_known( $directive ), $directive );
		}
	}

	public function test_login_defaults_have_no_frame_src() {
		$rules = Presets::defaults( 'login' );
		$this->assertArrayNotHasKey( 'frame-src', $rules );
		$this->assertArrayHasKey( 'form-action', $rules );
		$this->assertSame( array( "'self'", 'blob:' ), $rules['worker-src'] );
	}

	public function test_defaults_survive_normalisation() {
		foreach ( array( 'site', 'login' ) as $context ) {
			$map   = Presets::defaults( $context );
			$count = array_sum( array_map( 'count', $map ) );
			$this->assertCount( $count, Presets::to_rules( $map, 'default', 0 ), "$context: every default source is valid" );
		}
	}

	public function test_stripe_preset_covers_stripe_js_subdomains_and_address_autocomplete() {
		$rules = Presets::all()['stripe']['rules'];
		$this->assertContains( 'https://*.js.stripe.com', $rules['script-src'] );
		$this->assertContains( 'https://*.js.stripe.com', $rules['frame-src'] );
		$this->assertContains( 'https://maps.googleapis.com', $rules['script-src'] );
		$this->assertContains( 'https://maps.googleapis.com', $rules['connect-src'] );
	}

	public function test_default_rules_filter_receives_context() {
		Filters\expectApplied( 'codo_csp_default_rules' )->once()->with( \Mockery::type( 'array' ), 'login' )->andReturn( array( 'img-src' => array( '*' ) ) );
		$this->assertSame( array( 'img-src' => array( '*' ) ), Presets::defaults( 'login' ) );
	}

	public function test_default_rules_filter_returning_non_array_is_ignored() {
		Filters\expectApplied( 'codo_csp_default_rules' )->once()->andReturn( null );
		$this->assertArrayHasKey( 'frame-src', Presets::defaults( 'site' ) );
	}

	public function test_to_rules_expands_and_normalises() {
		$rules = Presets::to_rules(
			array(
				'script-src' => array( 'self', 'https://CDN.example.com/' ),
				'img-src'    => 'data:',
			),
			'preset:test',
			'1700000000'
		);
		$this->assertCount( 3, $rules );
		$this->assertSame(
			array(
				'd' => 'script-src',
				's' => "'self'",
				'o' => 'preset:test',
				't' => 1700000000,
				'n' => '',
			),
			$rules[0]
		);
		$this->assertSame( Source::normalise( 'script-src', 'https://CDN.example.com/' ), $rules[1]['s'] );
		$this->assertSame( 'img-src', $rules[2]['d'] );
		$this->assertSame( 'data:', $rules[2]['s'] );
	}

	public function test_to_rules_skips_invalid_sources() {
		$rules = Presets::to_rules(
			array(
				'img-src'    => array( '', 'https://ok.example.com', 'bad source; script-src *' ),
				'script-src' => array( "'unsafe-whatever'" ),
			),
			'default',
			1
		);
		$this->assertCount( 1, $rules );
		$this->assertSame( 'https://ok.example.com', $rules[0]['s'] );
	}

	public function test_to_rules_empty() {
		$this->assertSame( array(), Presets::to_rules( array(), 'default', 0 ) );
	}
}
