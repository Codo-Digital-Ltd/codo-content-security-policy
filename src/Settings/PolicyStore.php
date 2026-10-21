<?php
/**
 * Stores the live and draft policies for each context, and the multisite
 * network defaults.
 *
 * @package CodoDigital\Csp
 */

namespace CodoDigital\Csp\Settings;

use CodoDigital\Csp\Policy\Directives;
use CodoDigital\Csp\Policy\InvalidSourceException;
use CodoDigital\Csp\Policy\Policy;
use CodoDigital\Csp\Policy\Presets;
use CodoDigital\Csp\Policy\Source;

defined( 'ABSPATH' ) || exit;

/**
 * Policies live in the codo_csp_policy option.
 *
 * For example:
 *
 *     array(
 *         'site'  => array( 'rules' => array( ...rules ), 'draft' => null|array( 'rules' => ..., 't' => started ) ),
 *         'login' => array( ... ),
 *     )
 *
 * On multisite, network defaults live in the codo_csp_network_policy site
 * option and are merged into every site's policy (sites can add to them but
 * not remove them).
 *
 * How changes apply:
 *
 * - In Report-Only mode every change applies straight away (nothing is
 *   blocked, so there is nothing to protect).
 * - When enforcing, a change that only loosens the policy (adding a source)
 *   applies straight away, because it cannot block anything that loads now.
 * - When enforcing, a change that tightens it (removing a source, adding a
 *   directive that stops a fallback, adding a hash) goes into a draft. The
 *   draft is sent as Content-Security-Policy-Report-Only next to the live
 *   policy, so real visitors test it without anything being blocked, and is
 *   promoted when its reports are clean.
 */
class PolicyStore {

	const OPTION         = 'codo_csp_policy';
	const NETWORK_OPTION = 'codo_csp_network_policy';
	const CONTEXTS       = array( 'site', 'login' );

	/**
	 * Settings.
	 *
	 * @var Settings
	 */
	private $settings;

	/**
	 * Constructor.
	 *
	 * @param Settings $settings Settings.
	 */
	public function __construct( Settings $settings ) {
		$this->settings = $settings;
	}

	/**
	 * Whether a context name is valid.
	 *
	 * @param string $context Context.
	 * @return bool
	 */
	public static function is_context( $context ) {
		return in_array( $context, self::CONTEXTS, true );
	}

	/**
	 * Stored data.
	 *
	 * @return array<string, array{rules: array<int, mixed>, draft: array{rules: array<int, mixed>, t: int}|null}>
	 */
	private function data() {
		$stored = get_option( self::OPTION, array() );
		$data   = array();
		foreach ( self::CONTEXTS as $context ) {
			$entry            = is_array( $stored ) && isset( $stored[ $context ] ) && is_array( $stored[ $context ] ) ? $stored[ $context ] : array();
			$draft            = isset( $entry['draft'] ) && is_array( $entry['draft'] ) && isset( $entry['draft']['rules'] ) && is_array( $entry['draft']['rules'] ) ? $entry['draft'] : null;
			$data[ $context ] = array(
				'rules' => isset( $entry['rules'] ) && is_array( $entry['rules'] ) ? $entry['rules'] : array(),
				'draft' => null === $draft ? null : array(
					'rules' => $draft['rules'],
					't'     => isset( $draft['t'] ) ? (int) $draft['t'] : 0,
				),
			);
		}
		return $data;
	}

	/**
	 * Whether the policy option has been created.
	 *
	 * @return bool
	 */
	public function is_seeded() {
		return is_array( get_option( self::OPTION, false ) );
	}

	/**
	 * Create the default policies if none are stored yet.
	 *
	 * @return bool Whether defaults were written.
	 */
	public function seed() {
		if ( $this->is_seeded() ) {
			return false;
		}
		$data = array();
		foreach ( self::CONTEXTS as $context ) {
			$data[ $context ] = array(
				'rules' => Presets::to_rules( Presets::defaults( $context ), 'default', time() ),
				'draft' => null,
			);
		}
		update_option( self::OPTION, $data, true );
		return true;
	}

	/**
	 * This site's own rules (live).
	 *
	 * @param string $context Context.
	 * @return Policy
	 */
	public function local( $context ) {
		$data = $this->data();
		return new Policy( $data[ $context ]['rules'] );
	}

	/**
	 * This site's draft rules, if a draft exists.
	 *
	 * @param string $context Context.
	 * @return Policy|null
	 */
	public function local_draft( $context ) {
		$data = $this->data();
		return null === $data[ $context ]['draft'] ? null : new Policy( $data[ $context ]['draft']['rules'] );
	}

	/**
	 * When the draft was started.
	 *
	 * @param string $context Context.
	 * @return int 0 when there is no draft.
	 */
	public function draft_started( $context ) {
		$data = $this->data();
		return null === $data[ $context ]['draft'] ? 0 : $data[ $context ]['draft']['t'];
	}

	/**
	 * Network default rules (empty outside multisite).
	 *
	 * @param string $context Context.
	 * @return Policy
	 */
	public function network( $context ) {
		if ( ! is_multisite() ) {
			return new Policy();
		}
		$stored = get_site_option( self::NETWORK_OPTION, array() );
		return new Policy( is_array( $stored ) && isset( $stored[ $context ] ) && is_array( $stored[ $context ] ) ? $stored[ $context ] : array() );
	}

	/**
	 * The live policy: network defaults plus this site's rules.
	 *
	 * @param string $context Context.
	 * @return Policy
	 */
	public function live( $context ) {
		return self::compose( $this->network( $context ), $this->local( $context ) );
	}

	/**
	 * The draft policy being tested, if any.
	 *
	 * @param string $context Context.
	 * @return Policy|null
	 */
	public function draft( $context ) {
		$draft = $this->local_draft( $context );
		return null === $draft ? null : self::compose( $this->network( $context ), $draft );
	}

	/**
	 * Add a source.
	 *
	 * @param string $context   Context.
	 * @param string $directive Directive.
	 * @param string $raw       Source as entered.
	 * @param string $origin    Where the rule came from (manual, preset:x, report, scan).
	 * @param string $note      Note.
	 * @return array{source: string, target: string, inherited: string[]} target is live, draft or exists.
	 * @throws InvalidSourceException When the source is invalid.
	 */
	public function add( $context, $directive, $raw, $origin = 'manual', $note = '' ) {
		$source  = Source::normalise( $directive, $raw );
		$network = $this->network( $context );
		$local   = $this->local( $context );
		$draft   = $this->local_draft( $context );
		$base    = null === $draft ? $local : $draft;

		if ( self::compose( $network, $base )->has( $directive, $source ) && self::compose( $network, $local )->has( $directive, $source ) ) {
			return array(
				'source'    => $source,
				'target'    => 'exists',
				'inherited' => array(),
			);
		}

		if ( "'none'" === $source && count( array_diff( (array) self::compose( $network, $base )->sources( $directive ), array( "'none'" ) ) ) > 0 ) {
			throw new InvalidSourceException( esc_html__( '\'none\' only works on its own. Remove the other sources from this directive instead.', 'codo-content-security-policy' ) );
		}

		$rule = array(
			'd' => $directive,
			's' => $source,
			'o' => $origin,
			't' => time(),
			'n' => self::clean_note( $note ),
		);

		$new_local = $this->apply_add( $network, $local, $rule, $inherited );

		if ( ! $this->settings->is_enforcing() || self::compose( $network, $new_local )->is_loosening_of( self::compose( $network, $local ) ) ) {
			$data                      = $this->data();
			$data[ $context ]['rules'] = $new_local->rules();
			$draft_inherited           = array();
			$data[ $context ]['draft'] = null === $draft ? null : array(
				'rules' => $this->apply_add( $network, $draft, $rule, $draft_inherited )->rules(),
				't'     => $this->draft_started( $context ),
			);
			$this->save( $data, $context );
			return array(
				'source'    => $source,
				'target'    => 'live',
				'inherited' => $inherited,
			);
		}

		$new_draft = $this->apply_add( $network, $base, $rule, $inherited );
		$this->save_draft( $context, $new_draft );
		return array(
			'source'    => $source,
			'target'    => 'draft',
			'inherited' => $inherited,
		);
	}

	/**
	 * Network defaults merged into a site's rules.
	 *
	 * Each network rule is added the way a site rule would be: when it
	 * creates a fetch directive the site does not define (say style-src-elem),
	 * the sources the site inherited for it through fallback are copied in
	 * first. Without that, a network default for one host would replace the
	 * site's own 'self' and block its own stylesheets on every site at once.
	 *
	 * @param Policy $network Network rules.
	 * @param Policy $local   Site rules.
	 * @return Policy
	 */
	public static function compose( Policy $network, Policy $local ) {
		$result = $local;
		foreach ( $network->rules() as $rule ) {
			if ( $result->has( $rule['d'], $rule['s'] ) ) {
				continue;
			}
			$ignored = array();
			$result  = self::inherit_into( $result, $rule, $ignored );
		}
		return $result;
	}

	/**
	 * Add a rule, copying in inherited sources when it creates a fetch
	 * directive.
	 *
	 * @param Policy               $policy    Policy.
	 * @param array<string, mixed> $rule      Rule.
	 * @param string[]             $inherited Set to the sources copied in.
	 * @return Policy
	 */
	private static function inherit_into( Policy $policy, array $rule, &$inherited ) {
		$inherited = array();
		$directive = $rule['d'];

		// 'none' replaces whatever the directive inherited, so nothing is copied for it.
		if ( "'none'" !== $rule['s'] && Directives::is_fetch( $directive ) && ! $policy->defines( $directive ) ) {
			$fallback = $policy->effective( $directive );
			foreach ( null === $fallback ? array() : $fallback as $source ) {
				if ( "'none'" === $source || $source === $rule['s'] ) {
					continue;
				}
				try {
					$normalised = Source::normalise( $directive, $source );
				} catch ( InvalidSourceException $e ) {
					continue; // Had no effect on this resource type anyway.
				}
				$policy      = $policy->with(
					array(
						'd' => $directive,
						's' => $normalised,
						'o' => 'inherited',
						't' => isset( $rule['t'] ) ? (int) $rule['t'] : 0,
						'n' => '',
					)
				);
				$inherited[] = $normalised;
			}
		}

		if ( "'none'" !== $rule['s'] ) {
			$policy = $policy->without( $directive, "'none'" );
		}
		return $policy->with( $rule );
	}

	/**
	 * Add a rule to a local policy. When the directive is a fetch directive
	 * that is not defined yet, the sources it inherited through fallback are
	 * copied in first, so creating it does not block anything that loads now
	 * (frame-src without 'self' would otherwise block same-site iframes that
	 * default-src allowed).
	 *
	 * @param Policy               $network   Network rules.
	 * @param Policy               $local     Local rules.
	 * @param array<string, mixed> $rule      Rule.
	 * @param string[]|null        $inherited Set to the sources copied in.
	 * @return Policy
	 */
	private function apply_add( Policy $network, Policy $local, array $rule, &$inherited ) {
		// Work out what to copy in against the merged policy, but store only
		// the site's own rules (network rules are merged in when read).
		$merged = self::compose( $network, $local );
		$after  = self::inherit_into( $merged, $rule, $inherited );
		$result = $local->without( $rule['d'], "'none'" );
		if ( "'none'" === $rule['s'] ) {
			$result = $local;
		}
		foreach ( $after->diff( $merged ) as $added ) {
			$result = $result->with( $added );
		}
		return $result;
	}

	/**
	 * Remove a source.
	 *
	 * @param string $context   Context.
	 * @param string $directive Directive.
	 * @param string $source    Normalised source.
	 * @return string live, draft, or missing.
	 * @throws InvalidSourceException When the rule is a network default.
	 */
	public function remove( $context, $directive, $source ) {
		$network = $this->network( $context );
		$local   = $this->local( $context );
		$draft   = $this->local_draft( $context );

		if ( $network->has( $directive, $source ) ) {
			throw new InvalidSourceException( esc_html__( 'This source is a network default and can only be removed by a network administrator.', 'codo-content-security-policy' ) );
		}

		$in_live  = $local->has( $directive, $source );
		$in_draft = null !== $draft && $draft->has( $directive, $source );
		if ( ! $in_live && ! $in_draft ) {
			return 'missing';
		}

		$new_local = $local->without( $directive, $source );
		$loosening = self::compose( $network, $new_local )->is_loosening_of( self::compose( $network, $local ) );

		if ( $in_live && ( ! $this->settings->is_enforcing() || $loosening ) ) {
			$data                      = $this->data();
			$data[ $context ]['rules'] = $new_local->rules();
			if ( null !== $draft ) {
				$data[ $context ]['draft']['rules'] = $draft->without( $directive, $source )->rules();
			}
			$this->save( $data, $context );
			return 'live';
		}

		$base = null === $draft ? $local : $draft;
		$this->save_draft( $context, $base->without( $directive, $source ) );
		return 'draft';
	}

	/**
	 * Add every rule of a preset.
	 *
	 * @param string $context Context.
	 * @param string $id      Preset ID.
	 * @return int Rules added (0 for an unknown preset).
	 */
	public function apply_preset( $context, $id ) {
		$presets = Presets::all();
		if ( ! isset( $presets[ $id ]['rules'] ) || ! is_array( $presets[ $id ]['rules'] ) ) {
			return 0;
		}
		$added = 0;
		foreach ( $presets[ $id ]['rules'] as $directive => $sources ) {
			foreach ( (array) $sources as $source ) {
				try {
					$result = $this->add( $context, (string) $directive, (string) $source, 'preset:' . $id );
				} catch ( InvalidSourceException $e ) {
					continue;
				}
				if ( 'exists' !== $result['target'] ) {
					++$added;
				}
			}
		}
		return $added;
	}

	/**
	 * Make the draft live.
	 *
	 * @param string $context Context.
	 * @return bool Whether there was a draft.
	 */
	public function promote( $context ) {
		$data = $this->data();
		if ( null === $data[ $context ]['draft'] ) {
			return false;
		}
		$data[ $context ]['rules'] = $data[ $context ]['draft']['rules'];
		$data[ $context ]['draft'] = null;
		$this->save( $data, $context );
		return true;
	}

	/**
	 * Throw the draft away.
	 *
	 * @param string $context Context.
	 * @return bool Whether there was a draft.
	 */
	public function discard( $context ) {
		$data = $this->data();
		if ( null === $data[ $context ]['draft'] ) {
			return false;
		}
		$data[ $context ]['draft'] = null;
		$this->save( $data, $context );
		return true;
	}

	/**
	 * Promote every draft (used when switching back to Report-Only, where a
	 * draft has nothing left to protect).
	 *
	 * @return int Drafts promoted.
	 */
	public function promote_all() {
		$count = 0;
		foreach ( self::CONTEXTS as $context ) {
			if ( $this->promote( $context ) ) {
				++$count;
			}
		}
		return $count;
	}

	/**
	 * Add a network default (multisite).
	 *
	 * Network defaults apply to every site straight away; they can only add
	 * to a site's policy.
	 *
	 * @param string $context   Context.
	 * @param string $directive Directive.
	 * @param string $raw       Source as entered.
	 * @param string $note      Note.
	 * @return string Normalised source.
	 * @throws InvalidSourceException When invalid.
	 */
	public function network_add( $context, $directive, $raw, $note = '' ) {
		$source = Source::normalise( $directive, $raw );
		if ( "'none'" === $source || Source::cancels_unsafe_inline( $source ) ) {
			throw new InvalidSourceException( esc_html__( '\'none\', hashes and \'strict-dynamic\' restrict a policy rather than add to it, so they cannot be network defaults. Add them on each site, where they are tested in a draft first.', 'codo-content-security-policy' ) );
		}
		$rules = $this->network( $context )->with(
			array(
				'd' => $directive,
				's' => $source,
				'o' => 'network',
				't' => time(),
				'n' => self::clean_note( $note ),
			)
		);
		$this->save_network( $context, $rules );
		return $source;
	}

	/**
	 * Remove a network default (multisite). This can tighten the policy on
	 * every site that enforces it.
	 *
	 * @param string $context   Context.
	 * @param string $directive Directive.
	 * @param string $source    Normalised source.
	 * @return bool Whether it existed.
	 */
	public function network_remove( $context, $directive, $source ) {
		$network = $this->network( $context );
		if ( ! $network->has( $directive, $source ) ) {
			return false;
		}
		$this->save_network( $context, $network->without( $directive, $source ) );
		return true;
	}

	/**
	 * Save the network option.
	 *
	 * @param string $context Context.
	 * @param Policy $policy  Rules.
	 * @return void
	 */
	private function save_network( $context, Policy $policy ) {
		$stored = get_site_option( self::NETWORK_OPTION, array() );
		$stored = is_array( $stored ) ? $stored : array();

		$stored[ $context ] = $policy->rules();
		update_site_option( self::NETWORK_OPTION, $stored );

		/** This action is documented in src/Settings/PolicyStore.php */
		do_action( 'codo_csp_policy_changed', $context, 'network' );
	}

	/**
	 * Save a draft, keeping its start time.
	 *
	 * @param string $context Context.
	 * @param Policy $draft   Draft rules.
	 * @return void
	 */
	private function save_draft( $context, Policy $draft ) {
		$data                      = $this->data();
		$started                   = $this->draft_started( $context );
		$data[ $context ]['draft'] = array(
			'rules' => $draft->rules(),
			't'     => $started > 0 ? $started : time(),
		);
		$this->save( $data, $context );
	}

	/**
	 * Save and announce the change.
	 *
	 * @param array<string, mixed> $data    Data.
	 * @param string               $context Context changed.
	 * @return void
	 */
	private function save( array $data, $context ) {
		update_option( self::OPTION, $data, true );

		/**
		 * Fires after a policy changes (cached pages still carry the old header).
		 *
		 * @param string $context site or login.
		 * @param string $scope   site or network.
		 */
		do_action( 'codo_csp_policy_changed', $context, 'site' );
	}

	/**
	 * Notes are short plain text.
	 *
	 * @param string $note Note.
	 * @return string
	 */
	private static function clean_note( $note ) {
		return mb_substr( sanitize_text_field( (string) $note ), 0, 200 );
	}
}
