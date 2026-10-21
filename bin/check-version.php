<?php
/**
 * Checks that the plugin header, version constant and readme Stable tag agree,
 * and that the readme has a changelog entry for the version.
 *
 * Prints the version on success so CI can capture it.
 *
 * @package CodoDigital\Csp
 */

// phpcs:ignoreFile -- CLI build script, not shipped.

$root   = dirname( __DIR__ );
$plugin = file_get_contents( $root . '/codo-content-security-policy.php' );
$readme = file_get_contents( $root . '/readme.txt' );

$found = array(
	'plugin header'  => preg_match( '/^\s*\*\s*Version:\s*(\S+)/m', $plugin, $m ) ? $m[1] : null,
	'constant'       => preg_match( "/define\(\s*'CODO_CSP_VERSION',\s*'([^']+)'/", $plugin, $m ) ? $m[1] : null,
	'readme Stable tag' => preg_match( '/^Stable tag:\s*(\S+)/m', $readme, $m ) ? $m[1] : null,
);

$versions = array_unique( array_values( $found ) );
if ( in_array( null, $found, true ) || 1 !== count( $versions ) ) {
	fwrite( STDERR, "Version mismatch:\n" );
	foreach ( $found as $where => $version ) {
		fwrite( STDERR, sprintf( "  %-18s %s\n", $where, null === $version ? '(missing)' : $version ) );
	}
	exit( 1 );
}

$version = $versions[0];

if ( ! preg_match( '/^\d+\.\d+\.\d+$/', $version ) ) {
	fwrite( STDERR, "Version {$version} is not MAJOR.MINOR.PATCH.\n" );
	exit( 1 );
}

if ( false === strpos( $readme, '= ' . $version . ' =' ) ) {
	fwrite( STDERR, "readme.txt has no changelog entry \"= {$version} =\".\n" );
	exit( 1 );
}

echo $version, "\n";
