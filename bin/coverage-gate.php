<?php
/**
 * Fails the build when line coverage in a Clover report is below a threshold.
 *
 * Usage: php bin/coverage-gate.php build/clover.xml 95
 *
 * @package CodoDigital\Csp
 */

// phpcs:ignoreFile -- CLI build script, not shipped.

$file      = isset( $argv[1] ) ? $argv[1] : 'build/clover.xml';
$threshold = isset( $argv[2] ) ? (float) $argv[2] : 95.0;

if ( ! is_readable( $file ) ) {
	fwrite( STDERR, "Coverage report {$file} not found.\n" );
	exit( 1 );
}

$xml     = simplexml_load_file( $file );
$metrics = $xml->project->metrics;
$total   = (int) $metrics['statements'];
$covered = (int) $metrics['coveredstatements'];
$percent = $total > 0 ? $covered / $total * 100 : 0.0;

printf( "Line coverage: %.2f%% (%d/%d statements), threshold %.2f%%\n", $percent, $covered, $total, $threshold );

if ( $percent < $threshold ) {
	fwrite( STDERR, "Coverage is below the threshold.\n" );
	exit( 1 );
}
