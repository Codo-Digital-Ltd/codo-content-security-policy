<?php
/**
 * Normalises CSP violation reports from browsers.
 *
 * @package CodoDigital\Csp
 */

namespace CodoDigital\Csp\Reports;

use CodoDigital\Csp\Policy\Source;

defined( 'ABSPATH' ) || exit;

/**
 * Accepts both formats browsers send:
 *
 * - report-uri: application/csp-report, {"csp-report": {"document-uri", "blocked-uri", "effective-directive", ...}}
 * - Reporting API: application/reports+json, [{"type": "csp-violation", "url", "body": {"documentURL", "blockedURL", "effectiveDirective", "disposition"}}]
 *
 * Reports are untrusted input: anyone can post one. Only the fields needed
 * to aggregate are kept, reduced to safe shapes: the directive name, the
 * blocked origin (never the full URL, which may carry tokens) or a keyword
 * such as inline/eval, the document path without its query string, and the
 * disposition. Script samples, IP addresses and user agents are not stored.
 */
class ReportParser {

	const MAX_REPORTS = 50;

	/**
	 * Values browsers use for blocked-uri that are not URLs.
	 */
	const KEYWORDS = array( 'inline', 'eval', 'wasm-eval', 'trusted-types-policy', 'trusted-types-sink', 'self' );

	/**
	 * Parse a request body.
	 *
	 * @param string $body Raw JSON.
	 * @param string $home Site home URL; reports about other hosts are dropped.
	 * @return array<int, array{directive: string, blocked: string, document: string, disposition: string}>
	 */
	public function parse( $body, $home ) {
		$data = json_decode( (string) $body, true );
		if ( ! is_array( $data ) ) {
			return array();
		}

		$raw = array();
		if ( isset( $data['csp-report'] ) && is_array( $data['csp-report'] ) ) {
			$r     = $data['csp-report'];
			$raw[] = array(
				'document'    => isset( $r['document-uri'] ) ? $r['document-uri'] : '',
				'blocked'     => isset( $r['blocked-uri'] ) ? $r['blocked-uri'] : '',
				'directive'   => isset( $r['effective-directive'] ) ? $r['effective-directive'] : ( isset( $r['violated-directive'] ) ? $r['violated-directive'] : '' ),
				'disposition' => isset( $r['disposition'] ) ? $r['disposition'] : '',
				'source_file' => isset( $r['source-file'] ) ? $r['source-file'] : '',
			);
		} elseif ( array_keys( $data ) === range( 0, count( $data ) - 1 ) ) {
			foreach ( array_slice( $data, 0, self::MAX_REPORTS ) as $item ) {
				if ( ! is_array( $item ) || ! isset( $item['type'], $item['body'] ) || 'csp-violation' !== $item['type'] || ! is_array( $item['body'] ) ) {
					continue;
				}
				$b     = $item['body'];
				$raw[] = array(
					'document'    => isset( $b['documentURL'] ) ? $b['documentURL'] : ( isset( $item['url'] ) ? $item['url'] : '' ),
					'blocked'     => isset( $b['blockedURL'] ) ? $b['blockedURL'] : '',
					'directive'   => isset( $b['effectiveDirective'] ) ? $b['effectiveDirective'] : '',
					'disposition' => isset( $b['disposition'] ) ? $b['disposition'] : '',
					'source_file' => isset( $b['sourceFile'] ) ? $b['sourceFile'] : '',
				);
			}
		}

		$reports = array();
		foreach ( $raw as $report ) {
			$normalised = $this->normalise( $report, $home );
			if ( null !== $normalised ) {
				$reports[] = $normalised;
			}
		}
		return $reports;
	}

	/**
	 * Normalise one report.
	 *
	 * @param array<string, mixed> $report Raw fields.
	 * @param string               $home   Home URL.
	 * @return array{directive: string, blocked: string, document: string, disposition: string}|null
	 */
	private function normalise( array $report, $home ) {
		foreach ( $report as $value ) {
			if ( ! is_string( $value ) ) {
				return null;
			}
		}

		// "script-src-elem 'self'" (violated-directive) -> script-src-elem.
		$directive = strtolower( (string) strtok( trim( $report['directive'] ), ' ' ) );
		if ( ! preg_match( '/^[a-z][a-z\-]{1,39}$/', $directive ) ) {
			return null;
		}

		$document = Source::parse( $report['document'] );
		$site     = Source::parse( $home );
		if ( null === $document || null === $site || $document['host'] !== $site['host'] ) {
			return null;
		}

		// Browser extensions inject content that violates every policy; it is noise.
		$extension = '/^(chrome|moz|safari|safari-web|ms-browser)-extension:/i';
		if ( preg_match( $extension, $report['blocked'] ) || preg_match( $extension, $report['source_file'] ) ) {
			return null;
		}

		$blocked = $this->blocked( $report['blocked'] );
		if ( null === $blocked ) {
			return null;
		}

		$disposition = strtolower( $report['disposition'] );
		return array(
			'directive'   => $directive,
			'blocked'     => $blocked,
			'document'    => mb_substr( '' !== $document['path'] ? $document['path'] : '/', 0, 255 ),
			'disposition' => in_array( $disposition, array( 'enforce', 'report' ), true ) ? $disposition : '',
		);
	}

	/**
	 * Reduce the blocked value to an origin or keyword.
	 *
	 * @param string $blocked Raw value.
	 * @return string|null
	 */
	private function blocked( $blocked ) {
		$blocked = trim( $blocked );
		$lower   = strtolower( $blocked );
		if ( in_array( $lower, self::KEYWORDS, true ) ) {
			return $lower;
		}
		if ( in_array( $lower, array( 'data', 'blob' ), true ) ) {
			return $lower . ':';
		}
		$origin = Source::origin_of( $blocked );
		if ( null === $origin || strlen( $origin ) > 255 || ! preg_match( '~^[a-z][a-z0-9+.\-]*:(//[a-z0-9.\-\[\]:]+)?$~', $origin ) ) {
			return null;
		}
		return $origin;
	}
}
