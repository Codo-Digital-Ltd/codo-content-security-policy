<?php
/**
 * Reviews CSP rules found on a page before they can join the policy.
 *
 * @package CodoDigital\Csp
 */

namespace CodoDigital\Csp\Policy;

defined( 'ABSPATH' ) || exit;

/**
 * Every rule gets a verdict, worked out afresh against the current policy:
 * add (safe, ticked by default), confirm (risky, only imported when ticked),
 * refuse (never imported) or skip (not needed).
 *
 * Rules are only ever narrowed. Hosts are never merged into a wildcard, however
 * many share a domain: d111.cloudfront.net is one site's distribution, but
 * *.cloudfront.net is everyone's.
 */
final class ImportReview {

	const ADD     = 'add';
	const CONFIRM = 'confirm';
	const REFUSE  = 'refuse';
	const SKIP    = 'skip';

	/**
	 * Longest policy read. A longer one is ignored, not cut: a source cut in
	 * half can be a valid source for somebody else's host.
	 */
	const MAX_POLICY_BYTES = 16384;

	/**
	 * Most rules read from one page.
	 */
	const MAX_RULES = 500;

	/**
	 * Where data: and blob: only ever hold inert content.
	 */
	const INERT_DIRECTIVES = array( 'img-src', 'font-src', 'media-src' );

	/**
	 * Directives that open the page or its data to any host when wide open.
	 */
	const NEVER_ANY_HOST = array( 'frame-ancestors', 'form-action' );

	/**
	 * Split policy strings into directives, the way browsers read them: a
	 * comma starts another policy and a repeated directive is ignored.
	 *
	 * @param string[] $policies Header or meta values.
	 * @return array<int, array{directive: string, sources: string[]}>
	 */
	public static function parse( array $policies ) {
		$directives = array();
		foreach ( $policies as $value ) {
			if ( strlen( (string) $value ) > self::MAX_POLICY_BYTES ) {
				continue;
			}
			foreach ( explode( ',', (string) $value ) as $policy ) {
				$seen = array();
				foreach ( explode( ';', $policy ) as $part ) {
					$tokens = preg_split( '/\s+/', trim( $part ), -1, PREG_SPLIT_NO_EMPTY );
					if ( empty( $tokens ) ) {
						continue;
					}
					$name = strtolower( (string) array_shift( $tokens ) );
					if ( isset( $seen[ $name ] ) ) {
						continue;
					}
					$seen[ $name ] = true;
					// An empty source list means the same as 'none'.
					$directives[] = array(
						'directive' => $name,
						'sources'   => empty( $tokens ) && Directives::is_known( $name ) ? array( "'none'" ) : $tokens,
					);
				}
			}
		}
		return $directives;
	}

	/**
	 * Review the rules in some policies against the current policy.
	 *
	 * @param string[] $policies    Header or meta values.
	 * @param Policy   $current     Current policy.
	 * @param string   $page_origin Origin of the page they came from.
	 * @return array<int, array{directive: string, raw: string, source: string, verdict: string, reason: string}>
	 */
	public static function review( array $policies, Policy $current, $page_origin ) {
		$rows = array();
		foreach ( self::parse( $policies ) as $parsed ) {
			if ( ! Directives::is_known( $parsed['directive'] ) ) {
				$raw = implode( ' ', $parsed['sources'] );
				$row = self::row( $parsed['directive'], $raw, $raw, self::SKIP, self::unmanaged_reason( $parsed['directive'] ) );

				$rows[ self::key( $row ) ] = $row;
				continue;
			}
			foreach ( $parsed['sources'] as $raw ) {
				$row = self::assess( $parsed['directive'], $raw, $current, $page_origin );
				$key = self::key( $row );
				// The first sighting wins, so a refusal is never overwritten.
				$rows[ $key ] = isset( $rows[ $key ] ) ? $rows[ $key ] : $row;
			}
		}
		return array_slice( self::drop_redundant( $rows, $page_origin ), 0, self::MAX_RULES );
	}

	/**
	 * What the import form posts for a row.
	 *
	 * @param array<string, string> $row Row.
	 * @return string
	 */
	public static function key( array $row ) {
		return $row['directive'] . ' ' . $row['source'];
	}

	/**
	 * Rows that can still be imported.
	 *
	 * @param array<int, array<string, string>> $rows Rows.
	 * @return int
	 */
	public static function pending( array $rows ) {
		return count(
			array_filter(
				$rows,
				static function ( $row ) {
					return in_array( $row['verdict'], array( self::ADD, self::CONFIRM ), true );
				}
			)
		);
	}

	/**
	 * Findings about a whole policy, for after an import. It only reports:
	 * removing a rule stays the administrator's decision.
	 *
	 * @param Policy $policy      Policy.
	 * @param string $page_origin Page origin.
	 * @return string[]
	 */
	public static function audit( Policy $policy, $page_origin ) {
		$findings = array();
		foreach ( Directives::all() as $directive ) {
			$kept = $policy->sources( $directive );
			foreach ( $policy->sources( $directive ) as $source ) {
				$danger = self::danger( $directive, $source, $policy, $page_origin );
				if ( null !== $danger ) {
					$findings[] = $directive . ' ' . $source . ': ' . $danger[1];
				}
				$others = array_diff( $kept, array( $source ) );
				if ( self::is_covered( $source, $others, $page_origin ) ) {
					$kept       = $others;
					$findings[] = $directive . ' ' . $source . ': ' . __( 'another rule in this directive already covers it, so it can be removed.', 'codo-content-security-policy' );
				}
			}
		}
		return $findings;
	}

	/**
	 * Review one source.
	 *
	 * @param string $directive   Directive the policy manages.
	 * @param string $raw         Source as found.
	 * @param Policy $current     Current policy.
	 * @param string $page_origin Page origin.
	 * @return array{directive: string, raw: string, source: string, verdict: string, reason: string}
	 */
	private static function assess( $directive, $raw, Policy $current, $page_origin ) {
		try {
			$normal = Source::normalise( $directive, $raw );
		} catch ( InvalidSourceException $e ) {
			return self::row( $directive, $raw, $raw, self::REFUSE, html_entity_decode( $e->getMessage(), ENT_QUOTES ) );
		}

		$source = self::harden( $normal, $page_origin );
		$reason = $source !== $normal
			/* translators: %s: the source as it was found. */
			? sprintf( __( 'Tightened from %s.', 'codo-content-security-policy' ), $normal )
			: '';

		if ( $current->has( $directive, $source ) ) {
			return self::row( $directive, $raw, $source, self::SKIP, __( 'Already in your policy.', 'codo-content-security-policy' ) );
		}
		if ( "'none'" === $source && $current->defines( $directive ) ) {
			return self::row( $directive, $raw, $source, self::SKIP, __( 'Your policy lists sources here, and importing \'none\' would mean removing them.', 'codo-content-security-policy' ) );
		}
		// Adding beside 'none' replaces it, which would remove a rule and open what it closed.
		if ( array( "'none'" ) === $current->sources( $directive ) ) {
			return self::row( $directive, $raw, $source, self::REFUSE, __( 'Your policy deliberately blocks everything here with \'none\'.', 'codo-content-security-policy' ) );
		}

		$danger = self::danger( $directive, $source, $current, $page_origin );
		if ( null !== $danger && self::REFUSE === $danger[0] ) {
			return self::row( $directive, $raw, $source, self::REFUSE, $danger[1] );
		}
		$effective = $current->effective( $directive );
		if ( null !== $effective && self::is_covered( $source, $effective, $page_origin ) ) {
			return self::row( $directive, $raw, $source, self::SKIP, __( 'Your policy already allows this through a broader rule.', 'codo-content-security-policy' ) );
		}
		if ( null !== $danger ) {
			return self::row( $directive, $raw, $source, self::CONFIRM, trim( $danger[1] . ' ' . $reason ) );
		}
		return self::row( $directive, $raw, $source, self::ADD, $reason );
	}

	/**
	 * Tighten a source without changing what it is for: on an https site, use
	 * encrypted connections, and call the site itself 'self'.
	 *
	 * @param string $source      Normalised source.
	 * @param string $page_origin Page origin.
	 * @return string
	 */
	private static function harden( $source, $page_origin ) {
		if ( 0 !== strpos( (string) $page_origin, 'https://' ) ) {
			return $source;
		}
		// A custom port is left alone: the encrypted service may not be on it.
		$source = (string) preg_replace( array( '~^http://([^:/]+)(/|$)~', '~^ws://([^:/]+)(/|$)~' ), array( 'https://$1$2', 'wss://$1$2' ), $source );
		return $source === $page_origin ? "'self'" : $source;
	}

	/**
	 * Why a source is risky.
	 *
	 * @param string $directive   Directive.
	 * @param string $source      Normalised source.
	 * @param Policy $policy      Policy it would join.
	 * @param string $page_origin Page origin.
	 * @return array{0: string, 1: string}|null Verdict and reason; null when unremarkable.
	 */
	private static function danger( $directive, $source, Policy $policy, $page_origin ) {
		if ( 0 === strpos( $source, "'" ) ) {
			return self::keyword_danger( $directive, $source, $policy );
		}
		if ( preg_match( '/^[a-z][a-z0-9+.\-]*:$/', $source ) ) {
			return self::scheme_danger( $directive, $source );
		}
		if ( ! preg_match( '~^(?:([a-z][a-z0-9+.\-]*)://)?([^:/]+)(?::(\d+|\*))?(/.*)?$~', $source, $m ) ) {
			return null;
		}
		$scheme = $m[1];
		$host   = $m[2];

		if ( '*' === $host ) {
			return self::any_host_danger( $directive );
		}

		$problem = Source::host_problem( $directive, $source );
		if ( null !== $problem ) {
			return array( self::REFUSE, $problem );
		}
		$wildcard = 0 === strpos( $host, '*.' );
		$base     = $wildcard ? substr( $host, 2 ) : $host;
		if ( $wildcard ) {
			return array(
				self::CONFIRM,
				/* translators: %s: domain. */
				sprintf( __( 'Allows every subdomain of %s. Only import this if you control all of them; otherwise add the specific hosts.', 'codo-content-security-policy' ), $base ),
			);
		}

		if ( in_array( $scheme, array( 'http', 'ws' ), true ) && 0 === strpos( (string) $page_origin, 'https://' ) ) {
			return array( self::CONFIRM, __( 'Unencrypted, so anyone on the network path can change what it delivers.', 'codo-content-security-policy' ) );
		}
		if ( 'default-src' === $directive ) {
			return array( self::CONFIRM, __( 'default-src applies to every resource type without its own directive. Prefer the specific directive.', 'codo-content-security-policy' ) );
		}
		if ( in_array( $directive, array( 'object-src', 'base-uri' ), true ) ) {
			return array( self::CONFIRM, __( 'Another host here can take over how the page runs. This is rarely needed.', 'codo-content-security-policy' ) );
		}
		return null;
	}

	/**
	 * Why a keyword or hash is risky.
	 *
	 * @param string $directive Directive.
	 * @param string $source    Normalised source.
	 * @param Policy $policy    Policy it would join.
	 * @return array{0: string, 1: string}|null
	 */
	private static function keyword_danger( $directive, $source, Policy $policy ) {
		if ( Source::is_hash( $source ) ) {
			return in_array( "'unsafe-inline'", (array) $policy->effective( $directive ), true )
				? array( self::CONFIRM, __( 'Browsers ignore \'unsafe-inline\' once a hash is present, so this blocks other inline code that runs today.', 'codo-content-security-policy' ) )
				: null;
		}
		switch ( $source ) {
			case "'unsafe-eval'":
			case "'wasm-unsafe-eval'":
				return array( self::CONFIRM, __( 'Lets scripts turn strings into code. Only add it if something breaks without it.', 'codo-content-security-policy' ) );
			case "'unsafe-inline'":
				return array( self::CONFIRM, __( 'Inline code is allowed, so the policy does not stop injected inline code. Only add it if something breaks without it.', 'codo-content-security-policy' ) );
			case "'unsafe-hashes'":
				return array( self::CONFIRM, __( 'Lets matching inline event handlers run, which weakens protection against injected markup.', 'codo-content-security-policy' ) );
			case "'strict-dynamic'":
				return array( self::CONFIRM, __( 'Browsers ignore host sources and \'unsafe-inline\' once this is present, so this blocks scripts that load today.', 'codo-content-security-policy' ) );
		}
		return null;
	}

	/**
	 * Why a scheme source is risky.
	 *
	 * @param string $directive Directive.
	 * @param string $source    Scheme source.
	 * @return array{0: string, 1: string}|null
	 */
	private static function scheme_danger( $directive, $source ) {
		if ( in_array( $source, array( 'https:', 'http:', 'ws:', 'wss:' ), true ) ) {
			return self::any_host_danger( $directive );
		}
		if ( 'filesystem:' === $source ) {
			return array( self::REFUSE, __( 'filesystem: URLs are obsolete and can hold code from the page itself.', 'codo-content-security-policy' ) );
		}
		$blob_worker = 'worker-src' === $directive && 'blob:' === $source;
		if ( $blob_worker || ( in_array( $source, array( 'data:', 'blob:' ), true ) && in_array( $directive, self::INERT_DIRECTIVES, true ) ) ) {
			return null;
		}
		return array(
			self::CONFIRM,
			/* translators: 1: scheme such as data:, 2: directive. */
			sprintf( __( '%1$s URLs in %2$s can carry content from anywhere. Only import this if something breaks without it.', 'codo-content-security-policy' ), $source, $directive ),
		);
	}

	/**
	 * Why a source that matches any host is risky.
	 *
	 * @param string $directive Directive.
	 * @return array{0: string, 1: string}
	 */
	private static function any_host_danger( $directive ) {
		return in_array( $directive, self::NEVER_ANY_HOST, true )
			/* translators: %s: directive. */
			? array( self::REFUSE, sprintf( __( 'Any host in %s removes the protection this directive exists for.', 'codo-content-security-policy' ), $directive ) )
			: array( self::CONFIRM, __( 'Allows any host. Add the specific hosts instead.', 'codo-content-security-policy' ) );
	}

	/**
	 * Mark safe rows that another safe row already covers. Risky rows do not
	 * count as cover: they may stay unticked, and then nothing allows the host.
	 *
	 * @param array<string, array<string, string>> $rows        Rows by key.
	 * @param string                               $page_origin Page origin.
	 * @return array<int, array<string, string>>
	 */
	private static function drop_redundant( array $rows, $page_origin ) {
		foreach ( $rows as $key => $row ) {
			if ( self::ADD !== $row['verdict'] ) {
				continue;
			}
			$others = array();
			foreach ( $rows as $other_key => $other ) {
				if ( $other_key !== $key && self::ADD === $other['verdict'] && $other['directive'] === $row['directive'] ) {
					$others[] = $other['source'];
				}
			}
			if ( "'none'" === $row['source'] && ! empty( $others ) ) {
				$rows[ $key ]['verdict'] = self::SKIP;
				$rows[ $key ]['reason']  = __( 'Browsers ignore \'none\' when a directive lists other sources.', 'codo-content-security-policy' );
			} elseif ( self::is_covered( $row['source'], $others, $page_origin ) ) {
				$rows[ $key ]['verdict'] = self::SKIP;
				$rows[ $key ]['reason']  = __( 'Another rule in this import already covers it.', 'codo-content-security-policy' );
			}
		}
		return array_values( $rows );
	}

	/**
	 * Whether other sources already allow everything a source does.
	 *
	 * @param string   $source      Normalised source.
	 * @param string[] $others      Other sources.
	 * @param string   $page_origin Page origin.
	 * @return bool
	 */
	private static function is_covered( $source, array $others, $page_origin ) {
		$probe = self::probe( $source, $page_origin );
		if ( null === $probe ) {
			return false;
		}
		foreach ( $others as $other ) {
			if ( Source::matches( $other, $probe, $page_origin ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * A URL standing in for everything a source allows; whatever matches it
	 * covers the source. Null when no single URL can stand in.
	 *
	 * @param string $source      Normalised source.
	 * @param string $page_origin Page origin.
	 * @return string|null
	 */
	private static function probe( $source, $page_origin ) {
		if ( in_array( $source, array( 'data:', 'blob:' ), true ) ) {
			return $source . 'x';
		}
		if ( 0 === strpos( $source, "'" ) || preg_match( '/^[a-z][a-z0-9+.\-]*:$/', $source ) || '*' === $source || false !== strpos( $source, ':*' ) || preg_match( '~^(?:[a-z][a-z0-9+.\-]*://)?\*(?:[:/]|$)~', $source ) ) {
			return null;
		}
		// Only a parent wildcard matches a made-up subdomain; an exact host never does.
		$url = (string) preg_replace( '~^((?:[a-z][a-z0-9+.\-]*://)?)\*\.~', '$1codo-csp-probe.', $source );
		if ( false === strpos( $url, '://' ) ) {
			$page = Source::parse( $page_origin );
			$url  = ( null !== $page ? $page['scheme'] : 'https' ) . '://' . $url;
		}
		return $url;
	}

	/**
	 * Why a directive the plugin does not manage is left out.
	 *
	 * @param string $directive Directive.
	 * @return string
	 */
	private static function unmanaged_reason( $directive ) {
		switch ( $directive ) {
			case 'report-uri':
			case 'report-to':
				return __( 'Not imported, because it would send your visitors\' reports elsewhere. Reporting is set on the Settings tab.', 'codo-content-security-policy' );
			case 'upgrade-insecure-requests':
				return __( 'Not imported. This is an option on the Settings tab.', 'codo-content-security-policy' );
		}
		return __( 'This plugin does not manage this directive, so it is not imported. It stops applying if you remove the policy it came from.', 'codo-content-security-policy' );
	}

	/**
	 * A review row.
	 *
	 * @param string $directive Directive.
	 * @param string $raw       Source as found.
	 * @param string $source    Source that would be imported.
	 * @param string $verdict   Verdict.
	 * @param string $reason    Why.
	 * @return array{directive: string, raw: string, source: string, verdict: string, reason: string}
	 */
	private static function row( $directive, $raw, $source, $verdict, $reason ) {
		return array(
			'directive' => $directive,
			'raw'       => $raw,
			'source'    => $source,
			'verdict'   => $verdict,
			'reason'    => $reason,
		);
	}
}
