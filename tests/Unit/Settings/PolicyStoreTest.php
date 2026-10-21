<?php
/**
 * Tests for PolicyStore: live vs draft routing, inheritance, network defaults.
 *
 * @package CodoDigital\Csp\Tests
 */

namespace CodoDigital\Csp\Tests\Unit\Settings;

use Brain\Monkey\Actions;
use Brain\Monkey\Functions;
use CodoDigital\Csp\Policy\InvalidSourceException;
use CodoDigital\Csp\Policy\Policy;
use CodoDigital\Csp\Settings\PolicyStore;
use CodoDigital\Csp\Settings\Settings;
use CodoDigital\Csp\Tests\TestCase;

class PolicyStoreTest extends TestCase {

	/**
	 * Store with seeded defaults.
	 *
	 * @param string $mode Mode.
	 * @return PolicyStore
	 */
	private function store( $mode = Settings::MODE_REPORT_ONLY ) {
		$this->options[ Settings::OPTION ] = array( 'mode' => $mode );
		$store                             = new PolicyStore( new Settings() );
		$store->seed();
		return $store;
	}

	public function test_seeds_defaults_once() {
		$store = new PolicyStore( new Settings() );
		$this->assertFalse( $store->is_seeded() );
		$this->assertTrue( $store->seed() );
		$this->assertFalse( $store->seed() );
		$this->assertTrue( $store->live( 'site' )->has( 'frame-src', "'self'" ) );
		$this->assertFalse( $store->live( 'login' )->defines( 'frame-src' ) );
		$this->assertTrue( $store->live( 'login' )->has( 'object-src', "'none'" ) );
		$this->assertSame( 'default', $store->local( 'site' )->rules()[0]['o'] );
	}

	public function test_is_context() {
		$this->assertTrue( PolicyStore::is_context( 'login' ) );
		$this->assertFalse( PolicyStore::is_context( 'admin' ) );
	}

	public function test_tolerates_corrupt_option() {
		$this->options[ PolicyStore::OPTION ] = array(
			'site'  => 'garbage',
			'login' => array(
				'rules' => 'x',
				'draft' => array( 'rules' => 'y' ),
			),
		);
		$store = new PolicyStore( new Settings() );
		$this->assertSame( array(), $store->local( 'site' )->rules() );
		$this->assertNull( $store->local_draft( 'login' ) );
		$this->assertSame( 0, $store->draft_started( 'login' ) );
	}

	public function test_report_only_changes_apply_live() {
		$store = $this->store();
		Actions\expectDone( 'codo_csp_policy_changed' )->twice();

		$result = $store->add( 'site', 'script-src', 'https://cdn.example.com', 'manual', '<b>CDN</b>' );
		$this->assertSame( 'live', $result['target'] );
		$this->assertTrue( $store->live( 'site' )->has( 'script-src', 'https://cdn.example.com' ) );
		$this->assertSame( 'CDN', $store->local( 'site' )->rules()[ count( $store->local( 'site' )->rules() ) - 1 ]['n'] );

		$this->assertSame( 'live', $store->remove( 'site', 'script-src', "'unsafe-inline'" ) );
		$this->assertNull( $store->draft( 'site' ) );
	}

	public function test_existing_source_is_reported() {
		$store = $this->store();
		$this->assertSame( 'exists', $store->add( 'site', 'img-src', 'data:' )['target'] );
	}

	public function test_invalid_source_throws() {
		$store = $this->store();
		$this->expectException( InvalidSourceException::class );
		$store->add( 'site', 'script-src', '*' );
	}

	public function test_none_cannot_join_other_sources() {
		$store = $this->store();
		$this->expectException( InvalidSourceException::class );
		$store->add( 'site', 'img-src', "'none'" );
	}

	public function test_adding_to_a_none_directive_replaces_none() {
		$store  = $this->store( Settings::MODE_ENFORCE );
		$result = $store->add( 'site', 'object-src', 'https://player.example.com' );
		$this->assertSame( 'live', $result['target'] );
		$this->assertSame( array( 'https://player.example.com' ), $store->live( 'site' )->sources( 'object-src' ) );
	}

	public function test_new_directive_inherits_fallback_sources_so_it_stays_live() {
		$store  = $this->store( Settings::MODE_ENFORCE );
		$result = $store->add( 'site', 'media-src', 'https://media.example.com' );
		$this->assertSame( 'live', $result['target'] );
		$this->assertSame( array( "'self'" ), $result['inherited'] );
		$this->assertSame( array( "'self'", 'https://media.example.com' ), $store->live( 'site' )->sources( 'media-src' ) );
		$this->assertSame( 'inherited', $store->local( 'site' )->rules()[ count( $store->local( 'site' )->rules() ) - 2 ]['o'] );
	}

	public function test_inherited_sources_invalid_for_the_directive_are_skipped() {
		$this->options[ Settings::OPTION ]    = array( 'mode' => Settings::MODE_ENFORCE );
		$this->options[ PolicyStore::OPTION ] = array(
			'site' => array(
				'rules' => array(
					array(
						'd' => 'default-src',
						's' => "'self'",
					),
					array(
						'd' => 'default-src',
						's' => "'unsafe-inline'",
					),
				),
			),
		);
		$store  = new PolicyStore( new Settings() );
		$result = $store->add( 'site', 'img-src', 'data:' );
		$this->assertSame( array( "'self'" ), $result['inherited'] );
		$this->assertSame( 'live', $result['target'] );
	}

	public function test_enforced_tightening_add_goes_to_draft() {
		$store = $this->store( Settings::MODE_ENFORCE );

		$result = $store->add( 'site', 'script-src', "'sha256-abc'" );
		$this->assertSame( 'draft', $result['target'] );
		$this->assertFalse( $store->live( 'site' )->has( 'script-src', "'sha256-abc'" ) );
		$this->assertTrue( $store->draft( 'site' )->has( 'script-src', "'sha256-abc'" ) );
		$this->assertGreaterThan( 0, $store->draft_started( 'site' ) );
	}

	public function test_enforced_removal_goes_to_draft_and_loosening_changes_reach_both() {
		$store = $this->store( Settings::MODE_ENFORCE );

		$this->assertSame( 'draft', $store->remove( 'site', 'img-src', 'data:' ) );
		$this->assertTrue( $store->live( 'site' )->has( 'img-src', 'data:' ) );
		$this->assertFalse( $store->draft( 'site' )->has( 'img-src', 'data:' ) );

		// A loosening change goes live and into the open draft.
		$this->assertSame( 'live', $store->add( 'site', 'img-src', 'https://i.example.com' )['target'] );
		$this->assertTrue( $store->live( 'site' )->has( 'img-src', 'https://i.example.com' ) );
		$this->assertTrue( $store->draft( 'site' )->has( 'img-src', 'https://i.example.com' ) );

		// Second tightening change joins the same draft.
		$this->assertSame( 'draft', $store->remove( 'site', 'font-src', 'data:' ) );
		$this->assertFalse( $store->draft( 'site' )->has( 'font-src', 'data:' ) );
		$this->assertFalse( $store->draft( 'site' )->has( 'img-src', 'data:' ) );

		// "Keep": re-adding a source the draft removed restores it in the draft.
		$store->add( 'site', 'img-src', 'data:' );
		$this->assertTrue( $store->draft( 'site' )->has( 'img-src', 'data:' ) );
	}

	public function test_removing_a_draft_only_rule_edits_the_draft() {
		$store = $this->store( Settings::MODE_ENFORCE );
		$store->add( 'site', 'script-src', "'sha256-abc'" );
		$this->assertSame( 'draft', $store->remove( 'site', 'script-src', "'sha256-abc'" ) );
		$this->assertFalse( $store->draft( 'site' )->has( 'script-src', "'sha256-abc'" ) );
	}

	public function test_enforced_loosening_removal_applies_live_and_to_draft() {
		$store = $this->store( Settings::MODE_ENFORCE );
		$store->remove( 'site', 'img-src', 'data:' ); // Opens a draft.
		$this->assertSame( 'live', $store->remove( 'site', 'object-src', "'none'" ) );
		$this->assertFalse( $store->live( 'site' )->defines( 'object-src' ) );
		$this->assertFalse( $store->draft( 'site' )->defines( 'object-src' ) );
	}

	public function test_remove_missing_rule() {
		$store = $this->store();
		$this->assertSame( 'missing', $store->remove( 'site', 'img-src', 'https://nope.example.com' ) );
	}

	public function test_promote_and_discard() {
		$store = $this->store( Settings::MODE_ENFORCE );
		$this->assertFalse( $store->promote( 'site' ) );
		$this->assertFalse( $store->discard( 'site' ) );

		$store->remove( 'site', 'img-src', 'data:' );
		$this->assertTrue( $store->discard( 'site' ) );
		$this->assertTrue( $store->live( 'site' )->has( 'img-src', 'data:' ) );

		$store->remove( 'site', 'img-src', 'data:' );
		$this->assertTrue( $store->promote( 'site' ) );
		$this->assertFalse( $store->live( 'site' )->has( 'img-src', 'data:' ) );
		$this->assertNull( $store->draft( 'site' ) );
	}

	public function test_promote_all() {
		$store = $this->store( Settings::MODE_ENFORCE );
		$store->remove( 'site', 'img-src', 'data:' );
		$store->remove( 'login', 'img-src', 'data:' );
		$this->assertSame( 2, $store->promote_all() );
		$this->assertSame( 0, $store->promote_all() );
	}

	public function test_apply_preset() {
		$store = $this->store( Settings::MODE_ENFORCE );
		$added = $store->apply_preset( 'site', 'google-fonts' );
		$this->assertSame( 2, $added );
		$this->assertTrue( $store->live( 'site' )->has( 'font-src', 'https://fonts.gstatic.com' ) );
		$this->assertSame( 'preset:google-fonts', $store->local( 'site' )->rules()[ count( $store->local( 'site' )->rules() ) - 1 ]['o'] );
		$this->assertSame( 0, $store->apply_preset( 'site', 'google-fonts' ), 'Already present.' );
		$this->assertSame( 0, $store->apply_preset( 'site', 'nope' ) );
	}

	public function test_apply_preset_skips_invalid_sources() {
		$store = $this->store();
		Functions\when( 'apply_filters' )->alias(
			static function ( $hook, $value ) {
				if ( 'codo_csp_presets' === $hook ) {
					return array(
						'bad' => array(
							'label' => 'Bad',
							'rules' => array( 'script-src' => array( '*', 'https://ok.example.com' ) ),
						),
					);
				}
				return $value;
			}
		);
		$this->assertSame( 1, $store->apply_preset( 'site', 'bad' ) );
	}

	public function test_network_defaults_merge_and_cannot_be_removed_by_sites() {
		Functions\when( 'is_multisite' )->justReturn( true );
		$store = $this->store( Settings::MODE_ENFORCE );

		$this->assertSame( 'https://net.example.com', $store->network_add( 'site', 'script-src', 'https://NET.example.com', 'Agency' ) );
		$this->assertTrue( $store->live( 'site' )->has( 'script-src', 'https://net.example.com' ) );
		$this->assertFalse( $store->local( 'site' )->has( 'script-src', 'https://net.example.com' ) );
		$this->assertSame( 'exists', $store->add( 'site', 'script-src', 'https://net.example.com' )['target'] );

		try {
			$store->remove( 'site', 'script-src', 'https://net.example.com' );
			$this->fail( 'Expected an exception.' );
		} catch ( InvalidSourceException $e ) {
			$this->assertStringContainsString( 'network', $e->getMessage() );
		}

		// The draft also carries network defaults.
		$store->remove( 'site', 'img-src', 'data:' );
		$this->assertTrue( $store->draft( 'site' )->has( 'script-src', 'https://net.example.com' ) );

		$this->assertTrue( $store->network_remove( 'site', 'script-src', 'https://net.example.com' ) );
		$this->assertFalse( $store->network_remove( 'site', 'script-src', 'https://net.example.com' ) );
		$this->assertFalse( $store->live( 'site' )->has( 'script-src', 'https://net.example.com' ) );
	}

	/**
	 * Store with custom site rules (directive => sources) and multisite on.
	 *
	 * @param array<string, string[]> $site Site rules.
	 * @param string                  $mode Mode.
	 * @param string                  $context Context the rules are for.
	 * @return PolicyStore
	 */
	private function custom_store( array $site, $mode = Settings::MODE_ENFORCE, $context = 'site' ) {
		$this->options[ Settings::OPTION ] = array( 'mode' => $mode );
		$store                             = new PolicyStore( new Settings() );
		$store->seed();
		$this->options[ PolicyStore::OPTION ][ $context ]['rules'] = self::rules( $site )->rules();
		return $store;
	}

	/**
	 * A policy from a directive => sources map.
	 *
	 * @param array<string, string[]> $map Map.
	 * @return Policy
	 */
	private static function rules( array $map ) {
		$rules = array();
		foreach ( $map as $d => $sources ) {
			foreach ( $sources as $source ) {
				$rules[] = array(
					'd' => $d,
					's' => $source,
					'o' => 'manual',
					't' => 5,
				);
			}
		}
		return new Policy( $rules );
	}

	/**
	 * @return array<string, array{0: string}>
	 */
	public function restricting_sources() {
		return array(
			'hash'           => array( "'sha256-abc123='" ),
			'bare hash'      => array( 'sha384-abc' ),
			'strict-dynamic' => array( "'strict-dynamic'" ),
			'none'           => array( 'none' ),
		);
	}

	/**
	 * @dataProvider restricting_sources
	 */
	public function test_network_add_rejects_sources_that_restrict( $source ) {
		Functions\when( 'is_multisite' )->justReturn( true );
		$store = $this->store( Settings::MODE_ENFORCE );
		try {
			$store->network_add( 'site', 'script-src', $source );
			$this->fail( 'Expected an exception.' );
		} catch ( InvalidSourceException $e ) {
			$this->assertStringContainsString( 'cannot be network defaults', $e->getMessage() );
		}
		$this->assertSame( array(), $store->network( 'site' )->rules() );
		$this->assertArrayNotHasKey( PolicyStore::NETWORK_OPTION, $this->site_options );
	}

	public function test_network_style_src_elem_keeps_the_sites_own_styles() {
		Functions\when( 'is_multisite' )->justReturn( true );
		$store = $this->store( Settings::MODE_ENFORCE );
		$store->network_add( 'site', 'style-src-elem', 'https://fonts.googleapis.com' );

		$live = $store->live( 'site' );
		$this->assertSame( array( "'self'", "'unsafe-inline'", 'https://fonts.googleapis.com' ), $live->sources( 'style-src-elem' ) );
		$this->assertStringContainsString( "style-src-elem 'self' 'unsafe-inline' https://fonts.googleapis.com", $live->compile() );
		$this->assertTrue( $live->is_loosening_of( $store->local( 'site' ) ), 'the network default blocks nothing the site loads' );
		$this->assertFalse( $store->local( 'site' )->defines( 'style-src-elem' ), 'copied sources are not stored on the site' );

		$origins = array();
		foreach ( $live->rules() as $rule ) {
			if ( 'style-src-elem' === $rule['d'] ) {
				$origins[ $rule['s'] ] = $rule['o'];
			}
		}
		$this->assertSame(
			array(
				"'self'"                       => 'inherited',
				"'unsafe-inline'"              => 'inherited',
				'https://fonts.googleapis.com' => 'network',
			),
			$origins
		);
	}

	public function test_network_frame_src_on_login_inherits_default_src() {
		Functions\when( 'is_multisite' )->justReturn( true );
		$store = $this->store( Settings::MODE_ENFORCE );
		$this->assertFalse( $store->live( 'login' )->defines( 'frame-src' ) );

		$store->network_add( 'login', 'frame-src', 'https://challenges.cloudflare.com' );

		$this->assertSame( array( "'self'", 'https://challenges.cloudflare.com' ), $store->live( 'login' )->sources( 'frame-src' ) );
		$this->assertTrue( $store->live( 'login' )->allows( 'frame-src', 'https://www.example.com/frame', 'https://www.example.com' ) );
		$this->assertFalse( $store->live( 'site' )->has( 'frame-src', 'https://challenges.cloudflare.com' ), 'contexts are separate' );
	}

	public function test_network_defaults_also_inherit_into_the_draft() {
		Functions\when( 'is_multisite' )->justReturn( true );
		$store = $this->store( Settings::MODE_ENFORCE );
		$store->remove( 'login', 'img-src', 'data:' ); // Opens a draft.
		$store->network_add( 'login', 'media-src', 'https://media.network.test' );
		$this->assertSame( array( "'self'", 'https://media.network.test' ), $store->draft( 'login' )->sources( 'media-src' ) );
	}

	public function test_compose_without_network_rules_is_the_site_policy() {
		$local = self::rules( array( 'img-src' => array( "'self'" ) ) );
		$this->assertSame( $local->rules(), PolicyStore::compose( new Policy(), $local )->rules() );
	}

	public function test_compose_adds_to_defined_directives_without_copying() {
		$composed = PolicyStore::compose(
			self::rules( array( 'img-src' => array( 'https://net.example.com' ) ) ),
			self::rules(
				array(
					'default-src' => array( "'self'" ),
					'img-src'     => array( 'data:' ),
				)
			)
		);
		$this->assertSame( array( 'data:', 'https://net.example.com' ), $composed->sources( 'img-src' ) );
	}

	public function test_compose_skips_rules_the_site_already_has() {
		$local    = self::rules( array( 'img-src' => array( "'self'", 'https://net.example.com' ) ) );
		$composed = PolicyStore::compose( self::rules( array( 'img-src' => array( 'https://net.example.com' ) ) ), $local );
		$this->assertSame( $local->rules(), $composed->rules(), 'the site rule keeps its metadata' );
	}

	public function test_compose_does_not_copy_the_network_source_or_none() {
		// The inherited source equal to the network source is not copied twice.
		$composed = PolicyStore::compose(
			self::rules( array( 'frame-src' => array( "'self'" ) ) ),
			self::rules( array( 'default-src' => array( "'self'" ) ) )
		);
		$this->assertSame( array( "'self'" ), $composed->sources( 'frame-src' ) );
		$this->assertSame( 'manual', $composed->rules()[1]['o'] );

		// default-src 'none' is not copied into a directive a network rule creates.
		$composed = PolicyStore::compose(
			self::rules( array( 'img-src' => array( 'https://net.example.com' ) ) ),
			self::rules( array( 'default-src' => array( "'none'" ) ) )
		);
		$this->assertSame( array( 'https://net.example.com' ), $composed->sources( 'img-src' ) );
	}

	public function test_compose_replaces_none_and_ignores_standalone_fallbacks() {
		$composed = PolicyStore::compose(
			self::rules(
				array(
					'object-src'  => array( 'https://player.example.com' ),
					'form-action' => array( 'https://pay.example.com' ),
				)
			),
			self::rules(
				array(
					'default-src' => array( "'self'" ),
					'object-src'  => array( "'none'" ),
				)
			)
		);
		$this->assertSame( array( 'https://player.example.com' ), $composed->sources( 'object-src' ) );
		$this->assertSame( array( 'https://pay.example.com' ), $composed->sources( 'form-action' ), 'form-action does not fall back' );
	}

	public function test_compose_skips_inherited_sources_invalid_for_the_directive() {
		$composed = PolicyStore::compose(
			self::rules( array( 'worker-src' => array( 'https://w.example.com' ) ) ),
			self::rules(
				array(
					'default-src' => array( "'self'" ),
					'script-src'  => array( "'self'", "'unsafe-inline'", "'unsafe-eval'", 'https://cdn.example.com' ),
				)
			)
		);
		$this->assertSame( array( "'self'", 'https://cdn.example.com', 'https://w.example.com' ), $composed->sources( 'worker-src' ) );
	}

	public function test_adding_none_to_an_undefined_directive_copies_nothing() {
		$store  = $this->store();
		$result = $store->add( 'site', 'media-src', 'none' );
		$this->assertSame(
			array(
				'source'    => "'none'",
				'target'    => 'live',
				'inherited' => array(),
			),
			$result
		);
		$this->assertSame( array( "'none'" ), $store->live( 'site' )->sources( 'media-src' ) );
		$this->assertStringContainsString( "media-src 'none'", $store->live( 'site' )->compile() );
	}

	public function test_adding_none_to_an_undefined_directive_when_enforcing_goes_to_the_draft() {
		$store  = $this->store( Settings::MODE_ENFORCE );
		$result = $store->add( 'site', 'media-src', "'none'" );
		$this->assertSame( 'draft', $result['target'] );
		$this->assertSame( array(), $result['inherited'] );
		$this->assertFalse( $store->live( 'site' )->defines( 'media-src' ) );
		$this->assertStringContainsString( "media-src 'none'", $store->draft( 'site' )->compile() );
	}

	public function test_adding_a_source_to_a_none_directive_in_the_draft() {
		$store = $this->store( Settings::MODE_ENFORCE );
		$store->add( 'site', 'media-src', "'none'" );
		$result = $store->add( 'site', 'media-src', 'https://media.example.com' );
		$this->assertSame( 'live', $result['target'] );
		$this->assertSame( array( "'self'", 'https://media.example.com' ), $store->live( 'site' )->sources( 'media-src' ) );
		$this->assertSame( array( 'https://media.example.com' ), $store->draft( 'site' )->sources( 'media-src' ), 'the draft keeps its own choice, minus none' );
	}

	public function test_adding_the_inherited_source_itself_copies_nothing_else() {
		$store  = $this->store( Settings::MODE_ENFORCE );
		$result = $store->add( 'site', 'media-src', "'self'" );
		$this->assertSame( 'live', $result['target'] );
		$this->assertSame( array(), $result['inherited'] );
		$this->assertSame( array( "'self'" ), $store->live( 'site' )->sources( 'media-src' ) );
	}

	public function test_adding_to_worker_src_on_an_enforcing_site_goes_live() {
		$store  = $this->store( Settings::MODE_ENFORCE );
		$result = $store->add( 'site', 'worker-src', 'https://w.example.com' );
		$this->assertSame( 'live', $result['target'] );
		$this->assertNull( $store->draft( 'site' ) );
		$this->assertSame( array( "'self'", 'blob:', 'https://w.example.com' ), $store->live( 'site' )->sources( 'worker-src' ) );
	}

	public function test_creating_worker_src_on_an_enforcing_site_goes_live() {
		// Without worker-src, workers fall back to script-src, whose 'unsafe-inline' means nothing for them.
		$store  = $this->custom_store(
			array(
				'default-src' => array( "'self'" ),
				'script-src'  => array( "'self'", "'unsafe-inline'" ),
			)
		);
		$result = $store->add( 'site', 'worker-src', 'https://w.example.com' );
		$this->assertSame( 'live', $result['target'] );
		$this->assertSame( array( "'self'" ), $result['inherited'] );
		$this->assertNull( $store->draft( 'site' ) );
		$this->assertSame( array( "'self'", 'https://w.example.com' ), $store->live( 'site' )->sources( 'worker-src' ) );
	}

	public function test_creating_child_src_on_an_enforcing_site_goes_live() {
		$store  = $this->custom_store(
			array(
				'default-src' => array( "'self'" ),
				'script-src'  => array( "'self'", "'unsafe-inline'" ),
			)
		);
		$result = $store->add( 'site', 'child-src', 'https://frames.example.com' );
		$this->assertSame( 'live', $result['target'] );
		$this->assertSame( array( "'self'" ), $result['inherited'] );
		$this->assertNull( $store->draft( 'site' ) );
		$this->assertSame( array( "'self'", 'https://frames.example.com' ), $store->live( 'site' )->effective( 'worker-src' ) );
	}

	public function test_adding_to_child_src_with_the_default_policy_goes_live() {
		$store  = $this->store( Settings::MODE_ENFORCE );
		$result = $store->add( 'site', 'child-src', 'https://frames.example.com' );
		$this->assertSame( 'live', $result['target'] );
		$this->assertNull( $store->draft( 'site' ) );
	}

	public function test_site_add_copies_sources_against_the_composed_policy() {
		Functions\when( 'is_multisite' )->justReturn( true );
		$store = $this->store( Settings::MODE_ENFORCE );
		$store->network_add( 'site', 'style-src', 'https://net.example.com' );
		$result = $store->add( 'site', 'style-src-elem', 'https://fonts.googleapis.com' );
		$this->assertSame( 'live', $result['target'] );
		$this->assertSame( array( "'self'", "'unsafe-inline'", 'https://net.example.com' ), $result['inherited'] );
		$this->assertTrue( $store->local( 'site' )->has( 'style-src-elem', 'https://net.example.com' ) );
		$this->assertFalse( $store->local( 'site' )->has( 'style-src', 'https://net.example.com' ), 'network rules are not stored on the site' );
	}

	public function test_network_option_is_ignored_outside_multisite() {
		$this->site_options[ PolicyStore::NETWORK_OPTION ] = array(
			'site' => array(
				array(
					'd' => 'img-src',
					's' => 'https://net.example.com',
				),
			),
		);
		$store = $this->store();
		$this->assertFalse( $store->live( 'site' )->has( 'img-src', 'https://net.example.com' ) );
	}

	public function test_network_add_rejects_invalid_and_tolerates_corrupt_option() {
		Functions\when( 'is_multisite' )->justReturn( true );
		$this->site_options[ PolicyStore::NETWORK_OPTION ] = 'garbage';
		$store = $this->store();
		$store->network_add( 'login', 'img-src', 'https://net.example.com' );
		$this->assertTrue( $store->live( 'login' )->has( 'img-src', 'https://net.example.com' ) );

		$this->expectException( InvalidSourceException::class );
		$store->network_add( 'site', 'script-src', 'https:' );
	}
}
