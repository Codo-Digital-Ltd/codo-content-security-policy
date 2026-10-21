<?php
/**
 * PHPUnit bootstrap: unit tests run without WordPress, with core functions
 * mocked by Brain Monkey.
 *
 * @package CodoDigital\Csp\Tests
 */

define( 'ABSPATH', __DIR__ . '/fixtures/wordpress/' );
define( 'WPINC', 'wp-includes' );
define( 'ARRAY_A', 'ARRAY_A' );
define( 'MINUTE_IN_SECONDS', 60 );
define( 'HOUR_IN_SECONDS', 3600 );
define( 'DAY_IN_SECONDS', 86400 );
define( 'KB_IN_BYTES', 1024 );
define( 'CODO_CSP_VERSION', '1.0.0-test' );
define( 'CODO_CSP_FILE', dirname( __DIR__ ) . '/codo-content-security-policy.php' );
define( 'CODO_CSP_DIR', dirname( __DIR__ ) );

require_once dirname( __DIR__ ) . '/vendor/autoload.php';
require_once __DIR__ . '/stubs/class-wp-error.php';
require_once dirname( __DIR__ ) . '/src/Autoloader.php';

\CodoDigital\Csp\Autoloader::register( dirname( __DIR__ ) . '/src' );
