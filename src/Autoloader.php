<?php
/**
 * PSR-4 autoloader scoped to the plugin's own namespace.
 *
 * @package CodoDigital\Csp
 */

namespace CodoDigital\Csp;

defined( 'ABSPATH' ) || exit;

/**
 * Loads classes in the CodoDigital\Csp namespace from the src directory.
 */
final class Autoloader {

	const PREFIX = 'CodoDigital\\Csp\\';

	/**
	 * Base directory for the namespace.
	 *
	 * @var string
	 */
	private static $base_dir = '';

	/**
	 * Register the autoloader.
	 *
	 * @param string $base_dir Directory that maps to the namespace root.
	 * @return void
	 */
	public static function register( $base_dir ) {
		self::$base_dir = rtrim( $base_dir, '/\\' ) . '/';
		spl_autoload_register( array( __CLASS__, 'load' ) );
	}

	/**
	 * Load a class if it belongs to this plugin.
	 *
	 * @param string $class_name Fully qualified class name.
	 * @return bool Whether a file was loaded.
	 */
	public static function load( $class_name ) {
		if ( 0 !== strpos( $class_name, self::PREFIX ) ) {
			return false;
		}

		$relative = substr( $class_name, strlen( self::PREFIX ) );
		if ( ! preg_match( '/^[A-Za-z0-9_\\\\]+$/', $relative ) ) {
			return false;
		}

		$file = self::$base_dir . str_replace( '\\', '/', $relative ) . '.php';
		if ( ! is_readable( $file ) ) {
			return false;
		}

		require_once $file;
		return true;
	}
}
