<?php
/**
 * Plugin Name:       Codo Content Security Policy
 * Plugin URI:        https://github.com/Codo-Digital-Ltd/codo-content-security-policy
 * Description:       Content-Security-Policy headers for the front end and login page. Starts in Report-Only, with a draft policy for safe changes, built-in violation reports and asset scanning. Free, no upsells.
 * Version:           1.0.0
 * Requires at least: 6.2
 * Requires PHP:      7.4
 * Author:            Codo Digital
 * Author URI:        https://cododigital.co.uk
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       codo-content-security-policy
 *
 * @package CodoDigital\Csp
 */

defined( 'ABSPATH' ) || exit;

define( 'CODO_CSP_VERSION', '1.0.0' );
define( 'CODO_CSP_FILE', __FILE__ );
define( 'CODO_CSP_DIR', __DIR__ );

require_once __DIR__ . '/src/Autoloader.php';

\CodoDigital\Csp\Autoloader::register( __DIR__ . '/src' );

register_activation_hook( __FILE__, array( \CodoDigital\Csp\Plugin::class, 'activate' ) );
register_deactivation_hook( __FILE__, array( \CodoDigital\Csp\Plugin::class, 'deactivate' ) );

add_action( 'plugins_loaded', array( \CodoDigital\Csp\Plugin::class, 'boot' ), 1 );
