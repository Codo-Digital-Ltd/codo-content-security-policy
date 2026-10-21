<?php
/**
 * An immutable set of CSP rules.
 *
 * @package CodoDigital\Csp
 */

namespace CodoDigital\Csp\Policy;

defined( 'ABSPATH' ) || exit;

/**
 * A policy is a list of rules. Each rule is one source in one directive,
 * with where it came from, when it was added and an optional note.
 *
 * For example:
 *
 *     array( 'd' => 'img-src', 's' => 'https://i.ytimg.com', 'o' => 'preset:youtube', 't' => 1700000000, 'n' => '' )
 */
final class Policy {

	/**
	 * Rules.
	 *
	 * @var array<int, array{d: string, s: string, o: string, t: int, n: string}>
	 */
	private $rules = array();

	/**
	 * Constructor. Invalid or duplicate rules are dropped.
	 *
	 * @param array<int, mixed> $rules Rules.
	 */
	public function __construct( array $rules = array() ) {
		$seen = array();
		foreach ( $rules as $rule ) {
			if ( ! is_array( $rule ) || ! isset( $rule['d'], $rule['s'] ) || ! Directives::is_known( $rule['d'] ) || ! is_string( $rule['s'] ) || '' === $rule['s'] ) {
				continue;
			}
			$key = $rule['d'] . ' ' . $rule['s'];
			if ( isset( $seen[ $key ] ) ) {
				continue;
			}
			$seen[ $key ]  = true;
			$this->rules[] = array(
				'd' => $rule['d'],
				's' => $rule['s'],
				'o' => isset( $rule['o'] ) ? (string) $rule['o'] : 'manual',
				't' => isset( $rule['t'] ) ? (int) $rule['t'] : 0,
				'n' => isset( $rule['n'] ) ? (string) $rule['n'] : '',
			);
		}
	}

	/**
	 * All rules.
	 *
	 * @return array<int, array{d: string, s: string, o: string, t: int, n: string}>
	 */
	public function rules() {
		return $this->rules;
	}

	/**
	 * Whether the policy has a rule.
	 *
	 * @param string $directive Directive.
	 * @param string $source    Source.
	 * @return bool
	 */
	public function has( $directive, $source ) {
		foreach ( $this->rules as $rule ) {
			if ( $rule['d'] === $directive && $rule['s'] === $source ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Whether the policy defines a directive at all.
	 *
	 * @param string $directive Directive.
	 * @return bool
	 */
	public function defines( $directive ) {
		foreach ( $this->rules as $rule ) {
			if ( $rule['d'] === $directive ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Sources listed directly under a directive.
	 *
	 * @param string $directive Directive.
	 * @return string[]
	 */
	public function sources( $directive ) {
		$sources = array();
		foreach ( $this->rules as $rule ) {
			if ( $rule['d'] === $directive ) {
				$sources[] = $rule['s'];
			}
		}
		return $sources;
	}

	/**
	 * Sources that govern a directive after fallback, as the browser sees
	 * them ('none' is ignored when other sources are present).
	 *
	 * @param string $directive Directive.
	 * @return string[]|null Null when nothing restricts it.
	 */
	public function effective( $directive ) {
		foreach ( Directives::chain( $directive ) as $candidate ) {
			if ( $this->defines( $candidate ) ) {
				$sources = $this->sources( $candidate );
				if ( count( $sources ) > 1 ) {
					$sources = array_values( array_diff( $sources, array( "'none'" ) ) );
				}
				return $sources;
			}
		}
		return null;
	}

	/**
	 * A copy with a rule added.
	 *
	 * @param array<string, mixed> $rule Rule.
	 * @return self
	 */
	public function with( array $rule ) {
		return new self( array_merge( $this->rules, array( $rule ) ) );
	}

	/**
	 * A copy without a rule.
	 *
	 * @param string $directive Directive.
	 * @param string $source    Source.
	 * @return self
	 */
	public function without( $directive, $source ) {
		return new self(
			array_filter(
				$this->rules,
				static function ( $rule ) use ( $directive, $source ) {
					return ! ( $rule['d'] === $directive && $rule['s'] === $source );
				}
			)
		);
	}

	/**
	 * A copy without a whole directive.
	 *
	 * @param string $directive Directive.
	 * @return self
	 */
	public function without_directive( $directive ) {
		return new self(
			array_filter(
				$this->rules,
				static function ( $rule ) use ( $directive ) {
					return $rule['d'] !== $directive;
				}
			)
		);
	}

	/**
	 * Union with another policy (used for network defaults + site rules).
	 * Rules already here keep their metadata.
	 *
	 * @param Policy $other Other policy.
	 * @return self
	 */
	public function merge( Policy $other ) {
		return new self( array_merge( $this->rules, $other->rules() ) );
	}

	/**
	 * Rules here that $other lacks.
	 *
	 * @param Policy $other Other policy.
	 * @return array<int, array{d: string, s: string, o: string, t: int, n: string}>
	 */
	public function diff( Policy $other ) {
		return array_values(
			array_filter(
				$this->rules,
				static function ( $rule ) use ( $other ) {
					return ! $other->has( $rule['d'], $rule['s'] );
				}
			)
		);
	}

	/**
	 * Compile the header value.
	 *
	 * @param bool     $upgrade_insecure Add upgrade-insecure-requests.
	 * @param string[] $extra        Extra directive strings (reporting).
	 * @return string
	 */
	public function compile( $upgrade_insecure = false, array $extra = array() ) {
		$parts = array();
		foreach ( Directives::all() as $directive ) {
			if ( ! $this->defines( $directive ) ) {
				continue;
			}
			$sources = $this->sources( $directive );
			if ( count( $sources ) > 1 ) {
				$sources = array_diff( $sources, array( "'none'" ) );
			}
			$parts[] = $directive . ' ' . implode( ' ', $sources );
		}
		if ( $upgrade_insecure ) {
			$parts[] = 'upgrade-insecure-requests';
		}
		return implode( '; ', array_merge( $parts, $extra ) );
	}

	/**
	 * Whether this policy allows everything $old allows, i.e. switching
	 * from $old to this cannot block anything that currently loads.
	 *
	 * Checked per directive after fallback, so creating frame-src without
	 * 'self' (which default-src used to provide) counts as tightening. A new
	 * hash or 'strict-dynamic' also counts, because browsers then ignore
	 * 'unsafe-inline' (and 'strict-dynamic' ignores host sources).
	 *
	 * @param Policy $old Current policy.
	 * @return bool
	 */
	public function is_loosening_of( Policy $old ) {
		foreach ( Directives::all() as $directive ) {
			$before = self::meaningful( $directive, $old->effective( $directive ) );
			$after  = self::meaningful( $directive, $this->effective( $directive ) );
			if ( null === $after ) {
				continue;
			}
			if ( null === $before ) {
				return false;
			}
			if ( array( "'none'" ) === $before ) {
				continue;
			}
			$removed = array_diff( $before, $after );
			if ( self::inline_open( $after ) ) {
				// A hash adds nothing once every inline block is allowed.
				$removed = array_filter(
					$removed,
					static function ( $source ) {
						return ! Source::is_hash( $source );
					}
				);
			}
			if ( count( $removed ) > 0 ) {
				return false;
			}
			foreach ( array_diff( $after, $before ) as $added ) {
				if ( Source::cancels_unsafe_inline( $added ) ) {
					return false;
				}
			}
		}
		return true;
	}

	/**
	 * Drop sources that have no effect in a directive.
	 *
	 * @param string        $directive Directive.
	 * @param string[]|null $sources   Sources.
	 * @return string[]|null
	 */
	private static function meaningful( $directive, $sources ) {
		if ( null === $sources ) {
			return null;
		}
		return array_values(
			array_filter(
				$sources,
				static function ( $source ) use ( $directive ) {
					return Source::is_meaningful( $directive, $source );
				}
			)
		);
	}

	/**
	 * Whether a resource URL may load under a directive.
	 *
	 * @param string $directive Directive (e.g. script-src-elem).
	 * @param string $url       Absolute URL.
	 * @param string $page_origin      Page origin.
	 * @return bool
	 */
	public function allows( $directive, $url, $page_origin ) {
		$sources = $this->effective( $directive );
		if ( null === $sources ) {
			return true;
		}
		if ( in_array( "'strict-dynamic'", $sources, true ) && Directives::is_script( $directive ) ) {
			// Host sources are ignored; only hashed/nonced scripts load, which a scan cannot tell.
			return false;
		}
		foreach ( $sources as $source ) {
			if ( Source::matches( $source, $url, $page_origin ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Whether inline code (script, event handler, style element or
	 * attribute) is allowed under a directive.
	 *
	 * @param string $directive Directive (script-src-elem, script-src-attr, style-src-elem, style-src-attr).
	 * @return bool
	 */
	public function allows_inline( $directive ) {
		$sources = $this->effective( $directive );
		return null === $sources || self::inline_open( $sources );
	}

	/**
	 * Whether a source list allows all inline code: 'unsafe-inline' without
	 * a hash, nonce or 'strict-dynamic' that would make browsers ignore it.
	 *
	 * @param string[] $sources Sources.
	 * @return bool
	 */
	private static function inline_open( array $sources ) {
		if ( ! in_array( "'unsafe-inline'", $sources, true ) ) {
			return false;
		}
		foreach ( $sources as $source ) {
			if ( Source::cancels_unsafe_inline( $source ) ) {
				return false;
			}
		}
		return true;
	}
}
