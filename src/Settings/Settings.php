<?php
/**
 * Plugin settings, with wp-config.php constant overrides.
 *
 * @package CodoDigital\Csp
 */

namespace CodoDigital\Csp\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Settings stored in the codo_csp_settings option.
 *
 * Constants (all optional) override the database and show read-only:
 *
 * - CODO_CSP_DISABLE    true sends no headers at all (emergency switch).
 * - CODO_CSP_MODE       'report-only' or 'enforce'.
 * - CODO_CSP_REPORT_URI an external report collector URL; turns off the built-in endpoint.
 * - CODO_CSP_LOGIN      true/false to cover wp-login.php.
 */
class Settings {

	const OPTION = 'codo_csp_settings';

	const MODE_REPORT_ONLY = 'report-only';
	const MODE_ENFORCE     = 'enforce';

	const REPORTING_BUILTIN  = 'builtin';
	const REPORTING_EXTERNAL = 'external';
	const REPORTING_OFF      = 'off';

	/**
	 * Days the built-in collector runs for when started.
	 */
	const REPORT_WINDOWS = array( 1, 7, 30 );

	/**
	 * Cached values.
	 *
	 * @var array<string, mixed>|null
	 */
	private $values = null;

	/**
	 * Default values. The plugin starts in Report-Only with the built-in
	 * collector running for seven days from activation.
	 *
	 * @return array<string, mixed>
	 */
	public static function defaults() {
		return array(
			'mode'             => self::MODE_REPORT_ONLY,
			'reporting'        => self::REPORTING_BUILTIN,
			'report_until'     => 0,
			'external_uri'     => '',
			'report_token'     => '',
			'login_enabled'    => true,
			'skip_builders'    => true,
			'upgrade_insecure' => false,
			'purge_caches'     => true,
			'scan_on_save'     => true,
		);
	}

	/**
	 * All values, with constants applied.
	 *
	 * @return array<string, mixed>
	 */
	public function all() {
		if ( null === $this->values ) {
			$stored       = get_option( self::OPTION, array() );
			$this->values = array_merge( self::defaults(), is_array( $stored ) ? array_intersect_key( $stored, self::defaults() ) : array() );
		}
		$values = $this->values;
		foreach ( $this->constants() as $key => $value ) {
			$values[ $key ] = $value;
		}
		return $values;
	}

	/**
	 * One value.
	 *
	 * @param string $key Key.
	 * @return mixed
	 */
	public function get( $key ) {
		$all = $this->all();
		return isset( $all[ $key ] ) ? $all[ $key ] : null;
	}

	/**
	 * Values fixed by constants.
	 *
	 * @return array<string, mixed>
	 */
	public function constants() {
		$fixed = array();
		if ( defined( 'CODO_CSP_MODE' ) && in_array( constant( 'CODO_CSP_MODE' ), array( self::MODE_REPORT_ONLY, self::MODE_ENFORCE ), true ) ) {
			$fixed['mode'] = constant( 'CODO_CSP_MODE' );
		}
		if ( defined( 'CODO_CSP_REPORT_URI' ) ) {
			$uri                   = self::sanitize_uri( (string) constant( 'CODO_CSP_REPORT_URI' ) );
			$fixed['reporting']    = '' !== $uri ? self::REPORTING_EXTERNAL : self::REPORTING_OFF;
			$fixed['external_uri'] = $uri;
		}
		if ( defined( 'CODO_CSP_LOGIN' ) ) {
			$fixed['login_enabled'] = (bool) constant( 'CODO_CSP_LOGIN' );
		}
		return $fixed;
	}

	/**
	 * Whether a value is fixed by a constant.
	 *
	 * @param string $key Key.
	 * @return bool
	 */
	public function is_locked( $key ) {
		return array_key_exists( $key, $this->constants() );
	}

	/**
	 * Whether CODO_CSP_DISABLE switches all headers off.
	 *
	 * @return bool
	 */
	public function is_disabled() {
		return defined( 'CODO_CSP_DISABLE' ) && (bool) constant( 'CODO_CSP_DISABLE' );
	}

	/**
	 * Whether the policy is enforced (otherwise Report-Only).
	 *
	 * @return bool
	 */
	public function is_enforcing() {
		return self::MODE_ENFORCE === $this->get( 'mode' );
	}

	/**
	 * Save values (unknown keys are ignored, values are sanitised; values
	 * fixed by constants are stored but have no effect while defined).
	 *
	 * @param array<string, mixed> $changes Values to change.
	 * @return void
	 */
	public function update( array $changes ) {
		$stored = get_option( self::OPTION, array() );
		$values = array_merge( self::defaults(), is_array( $stored ) ? array_intersect_key( $stored, self::defaults() ) : array() );

		foreach ( $changes as $key => $value ) {
			if ( ! array_key_exists( $key, self::defaults() ) ) {
				continue;
			}
			$values[ $key ] = $this->sanitize( $key, $value );
		}

		update_option( self::OPTION, $values );
		$this->values = $values;
	}

	/**
	 * Sanitise one value.
	 *
	 * @param string $key   Key.
	 * @param mixed  $value Value.
	 * @return mixed
	 */
	private function sanitize( $key, $value ) {
		switch ( $key ) {
			case 'mode':
				return self::MODE_ENFORCE === $value ? self::MODE_ENFORCE : self::MODE_REPORT_ONLY;
			case 'reporting':
				return in_array( $value, array( self::REPORTING_BUILTIN, self::REPORTING_EXTERNAL, self::REPORTING_OFF ), true ) ? $value : self::REPORTING_OFF;
			case 'report_until':
				return max( 0, (int) $value );
			case 'external_uri':
				return self::sanitize_uri( (string) $value );
			case 'report_token':
				return preg_replace( '/[^A-Za-z0-9]/', '', (string) $value );
			default:
				return (bool) $value;
		}
	}

	/**
	 * Accept only absolute https URLs (http for localhost) without
	 * characters that could break out of the header.
	 *
	 * @param string $uri URI.
	 * @return string Empty when invalid.
	 */
	public static function sanitize_uri( $uri ) {
		$uri = trim( $uri );
		if ( '' === $uri || preg_match( '/[\s;,"\'<>\x00-\x1f\x7f]/', $uri ) ) {
			return '';
		}
		$parts = wp_parse_url( $uri );
		if ( ! is_array( $parts ) || empty( $parts['host'] ) || empty( $parts['scheme'] ) ) {
			return '';
		}
		$scheme = strtolower( $parts['scheme'] );
		if ( 'https' !== $scheme && ! ( 'http' === $scheme && in_array( $parts['host'], array( 'localhost', '127.0.0.1' ), true ) ) ) {
			return '';
		}
		return $uri;
	}

	/**
	 * The report token, created on first use.
	 *
	 * @return string
	 */
	public function report_token() {
		$token = (string) $this->get( 'report_token' );
		if ( '' === $token ) {
			$token = wp_generate_password( 20, false, false );
			$this->update( array( 'report_token' => $token ) );
			$token = (string) $this->get( 'report_token' );
		}
		return $token;
	}

	/**
	 * Whether the built-in collector is accepting reports now.
	 *
	 * @param int|null $now Timestamp.
	 * @return bool
	 */
	public function is_collecting( $now = null ) {
		$now = null === $now ? time() : $now;
		return self::REPORTING_BUILTIN === $this->get( 'reporting' ) && (int) $this->get( 'report_until' ) > $now;
	}

	/**
	 * Where browsers should send reports now, if anywhere.
	 *
	 * @param int|null $now     Timestamp.
	 * @param string   $context site or login (recorded with built-in reports).
	 * @return string Empty when reporting is off or the collection window has ended.
	 */
	public function report_uri( $now = null, $context = 'site' ) {
		if ( self::REPORTING_EXTERNAL === $this->get( 'reporting' ) ) {
			return (string) $this->get( 'external_uri' );
		}
		if ( ! $this->is_collecting( $now ) ) {
			return '';
		}
		$args = array( 'codo_csp_report' => $this->report_token() );
		if ( 'login' === $context ) {
			$args['ctx'] = 'login';
		}
		return add_query_arg( $args, home_url( '/' ) );
	}

	/**
	 * Start (or extend) built-in collection for a number of days.
	 *
	 * @param int      $days Days.
	 * @param int|null $now  Timestamp.
	 * @return void
	 */
	public function collect_for( $days, $now = null ) {
		$now  = null === $now ? time() : $now;
		$days = in_array( (int) $days, self::REPORT_WINDOWS, true ) ? (int) $days : 7;
		$this->update(
			array(
				'reporting'    => self::REPORTING_BUILTIN,
				'report_until' => $now + $days * DAY_IN_SECONDS,
			)
		);
	}

	/**
	 * Stop built-in collection now.
	 *
	 * @return void
	 */
	public function stop_collecting() {
		$this->update( array( 'report_until' => 0 ) );
	}

	/**
	 * Forget cached values (after another request changed them, and tests).
	 *
	 * @return void
	 */
	public function flush() {
		$this->values = null;
	}
}
