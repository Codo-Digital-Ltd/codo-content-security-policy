<?php
/**
 * Tests for ImportReview: parsing, safety verdicts, redundancy and the audit.
 *
 * @package CodoDigital\Csp\Tests
 */

namespace CodoDigital\Csp\Tests\Unit\Policy;

use CodoDigital\Csp\Policy\ImportReview;
use CodoDigital\Csp\Policy\Policy;
use CodoDigital\Csp\Tests\TestCase;

class ImportReviewTest extends TestCase {

	const ORIGIN = 'https://www.example.com';

	/**
	 * A policy from "directive source" pairs.
	 *
	 * @param array<int, array{0: string, 1: string}> $pairs Pairs.
	 * @return Policy
	 */
	private static function policy( array $pairs = array() ) {
		$rules = array();
		foreach ( $pairs as $pair ) {
			$rules[] = array(
				'd' => $pair[0],
				's' => $pair[1],
			);
		}
		return new Policy( $rules );
	}

	/**
	 * The verdict of one directive's only source.
	 *
	 * @param string $directive Directive.
	 * @param string $source    Source.
	 * @param Policy $current   Current policy.
	 * @return array<string, string>
	 */
	private static function one( $directive, $source, Policy $current = null ) {
		$rows = ImportReview::review( array( $directive . ' ' . $source ), null === $current ? self::policy() : $current, self::ORIGIN );
		return $rows[0];
	}

	/**
	 * @return array<string, array{0: string, 1: string, 2: string}>
	 */
	public function verdicts() {
		return array(
			'own distribution stays specific'  => array( 'script-src', 'https://d111.cloudfront.net', ImportReview::ADD ),
			'base cloudfront refused'          => array( 'script-src', 'cloudfront.net', ImportReview::REFUSE ),
			'cloudfront wildcard refused'      => array( 'script-src', '*.cloudfront.net', ImportReview::REFUSE ),
			'scheme wildcard refused'          => array( 'img-src', 'https://*.cloudfront.net', ImportReview::REFUSE ),
			'wildcard under shared refused'    => array( 'script-src', '*.s3.amazonaws.com', ImportReview::REFUSE ),
			'tenant host accepted'             => array( 'img-src', 'https://site.s3.amazonaws.com', ImportReview::ADD ),
			'lookalike is not shared'          => array( 'script-src', '*.notcloudfront.net', ImportReview::CONFIRM ),
			'whole tld refused'                => array( 'img-src', '*.com', ImportReview::REFUSE ),
			'whole country suffix refused'     => array( 'img-src', '*.co.uk', ImportReview::REFUSE ),
			'other wildcard needs a decision'  => array( 'img-src', '*.partner.com', ImportReview::CONFIRM ),
			'star in code refused'             => array( 'script-src', '*', ImportReview::REFUSE ),
			'https: in code refused'           => array( 'script-src', 'https:', ImportReview::REFUSE ),
			'data: in code refused'            => array( 'script-src', 'data:', ImportReview::REFUSE ),
			'star in images needs a decision'  => array( 'img-src', '*', ImportReview::CONFIRM ),
			'any host framing refused'         => array( 'frame-ancestors', '*', ImportReview::REFUSE ),
			'any https framing refused'        => array( 'frame-ancestors', 'https:', ImportReview::REFUSE ),
			'any host form target refused'     => array( 'form-action', 'https://*', ImportReview::REFUSE ),
			'nonce refused'                    => array( 'script-src', "'nonce-abc'", ImportReview::REFUSE ),
			'unknown keyword refused'          => array( 'script-src', "'nope'", ImportReview::REFUSE ),
			'keyword without effect refused'   => array( 'img-src', "'unsafe-inline'", ImportReview::REFUSE ),
			'filesystem refused'               => array( 'img-src', 'filesystem:', ImportReview::REFUSE ),
			'unsafe-eval needs a decision'     => array( 'script-src', "'unsafe-eval'", ImportReview::CONFIRM ),
			'wasm eval needs a decision'       => array( 'script-src', "'wasm-unsafe-eval'", ImportReview::CONFIRM ),
			'unsafe-inline needs a decision'   => array( 'style-src', "'unsafe-inline'", ImportReview::CONFIRM ),
			'unsafe-hashes needs a decision'   => array( 'script-src', "'unsafe-hashes'", ImportReview::CONFIRM ),
			'strict-dynamic needs a decision'  => array( 'script-src', "'strict-dynamic'", ImportReview::CONFIRM ),
			'open cdn refused for scripts'     => array( 'script-src', 'https://cdn.jsdelivr.net', ImportReview::REFUSE ),
			'open cdn path is fine'            => array( 'script-src', 'https://cdn.jsdelivr.net/npm/lib@1/', ImportReview::ADD ),
			'open cdn for images is fine'      => array( 'img-src', 'https://cdn.jsdelivr.net', ImportReview::ADD ),
			'default-src host needs decision'  => array( 'default-src', 'https://cdn.example.org', ImportReview::CONFIRM ),
			'object host needs a decision'     => array( 'object-src', 'https://cdn.example.org', ImportReview::CONFIRM ),
			'base-uri host needs a decision'   => array( 'base-uri', 'https://cdn.example.org', ImportReview::CONFIRM ),
			'data image is fine'               => array( 'img-src', 'data:', ImportReview::ADD ),
			'blob worker is fine'              => array( 'worker-src', 'blob:', ImportReview::ADD ),
			'data style needs a decision'      => array( 'style-src', 'data:', ImportReview::CONFIRM ),
			'custom port stays unencrypted'    => array( 'connect-src', 'http://api.example.org:8080', ImportReview::CONFIRM ),
			'self is fine'                     => array( 'script-src', "'self'", ImportReview::ADD ),
			'report-sample is fine'            => array( 'script-src', "'report-sample'", ImportReview::ADD ),
		);
	}

	/**
	 * @dataProvider verdicts
	 *
	 * @param string $directive Directive.
	 * @param string $source    Source.
	 * @param string $verdict   Expected verdict.
	 */
	public function test_verdicts( $directive, $source, $verdict ) {
		$this->assertSame( $verdict, self::one( $directive, $source )['verdict'] );
	}

	public function test_hosts_are_never_merged_into_a_wildcard() {
		$rows = ImportReview::review(
			array( 'script-src https://a1.cloudfront.net https://b2.cloudfront.net https://c3.cloudfront.net https://d4.cloudfront.net' ),
			self::policy(),
			self::ORIGIN
		);
		$this->assertSame(
			array( 'https://a1.cloudfront.net', 'https://b2.cloudfront.net', 'https://c3.cloudfront.net', 'https://d4.cloudfront.net' ),
			array_column( $rows, 'source' )
		);
		$this->assertSame( array( ImportReview::ADD ), array_values( array_unique( array_column( $rows, 'verdict' ) ) ) );
	}

	public function test_existing_rules_are_skipped_not_duplicated() {
		$row = self::one( 'img-src', 'HTTPS://CDN.Example.org/', self::policy( array( array( 'img-src', 'https://cdn.example.org' ) ) ) );
		$this->assertSame( ImportReview::SKIP, $row['verdict'] );
		$this->assertSame( 'https://cdn.example.org', $row['source'] );
	}

	public function test_rule_covered_by_a_broader_existing_rule_is_skipped() {
		$current = self::policy( array( array( 'img-src', '*.example.org' ) ) );
		$this->assertSame( ImportReview::SKIP, self::one( 'img-src', 'https://cdn.example.org', $current )['verdict'] );
		$this->assertSame( ImportReview::SKIP, self::one( 'img-src', '*.cdn.example.org', $current )['verdict'] );
		$this->assertSame( ImportReview::ADD, self::one( 'img-src', 'https://example.org.evil.test', $current )['verdict'] );
	}

	public function test_rule_covered_through_fallback_is_skipped() {
		$current = self::policy( array( array( 'default-src', 'https://cdn.example.org' ) ) );
		$this->assertSame( ImportReview::SKIP, self::one( 'img-src', 'https://cdn.example.org', $current )['verdict'] );
	}

	public function test_nothing_restricting_a_directive_is_not_cover() {
		$this->assertSame( ImportReview::ADD, self::one( 'img-src', 'https://cdn.example.org' )['verdict'] );
	}

	public function test_a_path_does_not_cover_the_whole_host() {
		$current = self::policy( array( array( 'img-src', 'https://cdn.example.org/a/' ) ) );
		$this->assertSame( ImportReview::ADD, self::one( 'img-src', 'https://cdn.example.org', $current )['verdict'] );
		$this->assertSame( ImportReview::SKIP, self::one( 'img-src', 'https://cdn.example.org/a/b.png', $current )['verdict'] );
	}

	public function test_refused_shared_wildcard_is_not_skipped_as_covered() {
		$current = self::policy( array( array( 'img-src', 'https:' ) ) );
		$this->assertSame( ImportReview::REFUSE, self::one( 'img-src', '*.cloudfront.net', $current )['verdict'] );
	}

	public function test_import_never_replaces_none() {
		$current = self::policy( array( array( 'object-src', "'none'" ) ) );
		$row     = self::one( 'object-src', "'self'", $current );
		$this->assertSame( ImportReview::REFUSE, $row['verdict'] );
		$this->assertSame( ImportReview::SKIP, self::one( 'object-src', "'none'", $current )['verdict'] );
	}

	public function test_none_is_not_imported_over_existing_sources() {
		$current = self::policy( array( array( 'img-src', "'self'" ) ) );
		$this->assertSame( ImportReview::SKIP, self::one( 'img-src', "'none'", $current )['verdict'] );
	}

	public function test_empty_source_list_means_none() {
		$rows = ImportReview::review( array( 'object-src' ), self::policy(), self::ORIGIN );
		$this->assertSame( "'none'", $rows[0]['source'] );
		$this->assertSame( ImportReview::ADD, $rows[0]['verdict'] );
	}

	public function test_none_beside_other_safe_sources_is_skipped() {
		$rows = ImportReview::review( array( "img-src 'none' https://cdn.example.org" ), self::policy(), self::ORIGIN );
		$this->assertSame( ImportReview::SKIP, $rows[0]['verdict'] );
		$this->assertSame( ImportReview::ADD, $rows[1]['verdict'] );
	}

	public function test_unencrypted_sources_are_tightened_on_https_sites() {
		$http = self::one( 'img-src', 'http://cdn.example.org/a/' );
		$this->assertSame( 'https://cdn.example.org/a/', $http['source'] );
		$this->assertSame( ImportReview::ADD, $http['verdict'] );
		$this->assertStringContainsString( 'http://cdn.example.org/a/', $http['reason'] );
		$this->assertSame( 'wss://live.example.org', self::one( 'connect-src', 'ws://live.example.org' )['source'] );
	}

	public function test_unencrypted_sources_stay_on_http_sites() {
		$rows = ImportReview::review( array( 'img-src http://cdn.example.org' ), self::policy(), 'http://www.example.com' );
		$this->assertSame( 'http://cdn.example.org', $rows[0]['source'] );
		$this->assertSame( ImportReview::ADD, $rows[0]['verdict'] );
	}

	public function test_the_site_itself_becomes_self() {
		$this->assertSame( "'self'", self::one( 'img-src', 'https://www.example.com/' )['source'] );
	}

	public function test_hash_warns_only_when_it_would_cancel_unsafe_inline() {
		$hash = "'sha256-" . str_repeat( 'a', 43 ) . "='";
		$this->assertSame( ImportReview::ADD, self::one( 'script-src', $hash )['verdict'] );
		$this->assertSame( ImportReview::CONFIRM, self::one( 'script-src', $hash, self::policy( array( array( 'script-src', "'unsafe-inline'" ) ) ) )['verdict'] );
	}

	public function test_rules_covered_within_the_import_are_skipped_once() {
		$rows = ImportReview::review( array( 'img-src https://a.example.org a.example.org' ), self::policy(), self::ORIGIN );
		$this->assertSame( array( ImportReview::SKIP, ImportReview::ADD ), array_column( $rows, 'verdict' ) );
	}

	public function test_a_risky_wildcard_is_not_cover_for_a_safe_host() {
		$rows = ImportReview::review( array( 'img-src *.example.org https://a.example.org' ), self::policy(), self::ORIGIN );
		$this->assertSame( array( ImportReview::CONFIRM, ImportReview::ADD ), array_column( $rows, 'verdict' ) );
	}

	public function test_same_rule_in_two_policies_is_listed_once() {
		$rows = ImportReview::review( array( 'img-src https://a.example.org', 'img-src https://a.example.org' ), self::policy(), self::ORIGIN );
		$this->assertCount( 1, $rows );
	}

	public function test_parse_splits_policies_and_ignores_repeated_directives() {
		$parsed = ImportReview::parse( array( 'IMG-SRC a.example.org; img-src b.example.org;; font-src c.example.org, img-src d.example.org' ) );
		$this->assertSame(
			array(
				array(
					'directive' => 'img-src',
					'sources'   => array( 'a.example.org' ),
				),
				array(
					'directive' => 'font-src',
					'sources'   => array( 'c.example.org' ),
				),
				array(
					'directive' => 'img-src',
					'sources'   => array( 'd.example.org' ),
				),
			),
			$parsed
		);
	}

	public function test_oversized_policy_is_ignored_rather_than_cut() {
		$this->assertSame( array(), ImportReview::parse( array( 'img-src ' . str_repeat( 'a', ImportReview::MAX_POLICY_BYTES ) ) ) );
	}

	public function test_rows_are_capped() {
		$hosts = array();
		for ( $i = 0; $i < ImportReview::MAX_RULES + 5; $i++ ) {
			$hosts[] = 'h' . $i . '.example.org';
		}
		$this->assertCount( ImportReview::MAX_RULES, ImportReview::review( array( 'img-src ' . implode( ' ', $hosts ) ), self::policy(), self::ORIGIN ) );
	}

	public function test_unmanaged_directives_are_listed_but_never_importable() {
		$rows = ImportReview::review( array( 'report-uri https://evil.example/r; report-to g; upgrade-insecure-requests; sandbox allow-scripts' ), self::policy(), self::ORIGIN );
		$this->assertSame( array( 'report-uri', 'report-to', 'upgrade-insecure-requests', 'sandbox' ), array_column( $rows, 'directive' ) );
		$this->assertSame( array( ImportReview::SKIP ), array_values( array_unique( array_column( $rows, 'verdict' ) ) ) );
		$this->assertSame( 0, ImportReview::pending( $rows ) );
	}

	public function test_pending_counts_safe_and_risky_rows() {
		$rows = ImportReview::review( array( "img-src https://a.example.org *.example.net *.cloudfront.net; script-src 'unsafe-eval'" ), self::policy(), self::ORIGIN );
		$this->assertSame( 3, ImportReview::pending( $rows ) );
	}

	public function test_audit_reports_risky_and_redundant_rules_without_changing_them() {
		$policy   = self::policy(
			array(
				array( 'script-src', "'unsafe-eval'" ),
				array( 'img-src', '*.cloudfront.net' ),
				array( 'font-src', '*.example.org' ),
				array( 'font-src', 'https://a.example.org' ),
				array( 'connect-src', "'self'" ),
			)
		);
		$before   = $policy->rules();
		$findings = implode( "\n", ImportReview::audit( $policy, self::ORIGIN ) );

		$this->assertStringContainsString( "script-src 'unsafe-eval':", $findings );
		$this->assertStringContainsString( 'img-src *.cloudfront.net:', $findings );
		$this->assertStringContainsString( 'font-src https://a.example.org: another rule', $findings );
		$this->assertStringNotContainsString( 'connect-src', $findings );
		$this->assertSame( $before, $policy->rules() );
	}

	public function test_audit_of_a_clean_policy_finds_nothing() {
		$this->assertSame( array(), ImportReview::audit( self::policy( array( array( 'img-src', "'self'" ), array( 'img-src', 'https://a.example.org' ) ) ), self::ORIGIN ) );
	}
}
