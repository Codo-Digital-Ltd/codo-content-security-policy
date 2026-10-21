<?php
/**
 * Base test case.
 *
 * @package CodoDigital\Csp\Tests
 */

namespace CodoDigital\Csp\Tests;

use Brain\Monkey;
use Brain\Monkey\Functions;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;

/**
 * Sets up Brain Monkey, common WordPress stubs and an in-memory option store.
 */
abstract class TestCase extends \PHPUnit\Framework\TestCase {

	use MockeryPHPUnitIntegration;

	/**
	 * In-memory options.
	 *
	 * @var array<string, mixed>
	 */
	protected $options = array();

	/**
	 * In-memory network options.
	 *
	 * @var array<string, mixed>
	 */
	protected $site_options = array();

	/**
	 * In-memory transients.
	 *
	 * @var array<string, mixed>
	 */
	protected $transients = array();

	protected function setUp(): void {
		parent::setUp();
		Monkey\setUp();

		$this->options      = array();
		$this->site_options = array();
		$this->transients   = array();

		Functions\stubTranslationFunctions();
		Functions\stubEscapeFunctions();
		Functions\stubs(
			array(
				'wp_json_encode'      => static function ( $data ) {
					return json_encode( $data );
				},
				'wp_parse_url'        => static function ( $url, $component = -1 ) {
					return parse_url( $url, $component );
				},
				'sanitize_text_field' => static function ( $text ) {
					return trim( strip_tags( (string) $text ) );
				},
				'sanitize_key'        => static function ( $key ) {
					return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( (string) $key ) );
				},
				'wp_unslash'          => static function ( $value ) {
					return $value;
				},
				'absint'              => static function ( $value ) {
					return abs( (int) $value );
				},
				'home_url'            => static function ( $path = '' ) {
					return 'https://www.example.com' . ( '' === $path ? '' : '/' . ltrim( $path, '/' ) );
				},
				'admin_url'           => static function ( $path = '' ) {
					return 'https://www.example.com/wp-admin/' . ltrim( $path, '/' );
				},
				'network_admin_url'   => static function ( $path = '' ) {
					return 'https://www.example.com/wp-admin/network/' . ltrim( $path, '/' );
				},
				'add_query_arg'       => static function ( $args, $url = '' ) {
					if ( is_string( $args ) ) {
						$args = array( $args => $url );
						$url  = func_num_args() > 2 ? func_get_arg( 2 ) : '';
					}
					return $url . ( false === strpos( $url, '?' ) ? '?' : '&' ) . http_build_query( $args );
				},
				'is_wp_error'         => static function ( $thing ) {
					return $thing instanceof \WP_Error;
				},
				'is_multisite'        => false,
				'get_current_user_id' => 1,
				'plugin_basename'     => 'codo-content-security-policy/codo-content-security-policy.php',
				'wp_date'             => static function ( $format, $timestamp = null ) {
					return gmdate( 'Y-m-d H:i', (int) $timestamp );
				},
				'size_format'         => static function ( $bytes ) {
					return $bytes . ' B';
				},
				'number_format_i18n'  => static function ( $number ) {
					return (string) $number;
				},
				'esc_url_raw'         => static function ( $url ) {
					return (string) $url;
				},
				'get_option'          => function ( $name, $default = false ) {
					if ( 'date_format' === $name ) {
						return 'Y-m-d';
					}
					if ( 'time_format' === $name ) {
						return 'H:i';
					}
					return array_key_exists( $name, $this->options ) ? $this->options[ $name ] : $default;
				},
				'update_option'       => function ( $name, $value ) {
					$this->options[ $name ] = $value;
					return true;
				},
				'delete_option'       => function ( $name ) {
					unset( $this->options[ $name ] );
					return true;
				},
				'get_site_option'     => function ( $name, $default = false ) {
					return array_key_exists( $name, $this->site_options ) ? $this->site_options[ $name ] : $default;
				},
				'update_site_option'  => function ( $name, $value ) {
					$this->site_options[ $name ] = $value;
					return true;
				},
				'delete_site_option'  => function ( $name ) {
					unset( $this->site_options[ $name ] );
					return true;
				},
				'get_transient'       => function ( $name ) {
					return array_key_exists( $name, $this->transients ) ? $this->transients[ $name ] : false;
				},
				'set_transient'       => function ( $name, $value ) {
					$this->transients[ $name ] = $value;
					return true;
				},
				'delete_transient'    => function ( $name ) {
					unset( $this->transients[ $name ] );
					return true;
				},
			)
		);
	}

	protected function tearDown(): void {
		Monkey\tearDown();
		parent::tearDown();
	}
}
