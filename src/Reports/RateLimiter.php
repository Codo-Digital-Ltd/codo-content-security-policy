<?php
/**
 * Caps how many report requests are processed per minute.
 *
 * @package CodoDigital\Csp
 */

namespace CodoDigital\Csp\Reports;

defined( 'ABSPATH' ) || exit;

/**
 * A fixed-window counter: in the object cache when a persistent one is
 * available, otherwise in a transient.
 */
class RateLimiter {

	const TRANSIENT = 'codo_csp_report_rate';
	const GROUP     = 'codo_csp';
	const LIMIT     = 120;

	/**
	 * Requests allowed per minute.
	 *
	 * @return int
	 */
	public function limit() {
		/**
		 * Filters how many report requests are processed per minute. The
		 * rest are answered without being read.
		 *
		 * @param int $limit Requests per minute.
		 */
		return max( 1, (int) apply_filters( 'codo_csp_report_rate_limit', self::LIMIT ) );
	}

	/**
	 * Count a request and say whether it may be processed.
	 *
	 * @param int|null $now Timestamp.
	 * @return bool
	 */
	public function allow( $now = null ) {
		$now    = null === $now ? time() : $now;
		$window = (int) floor( $now / 60 );
		$limit  = $this->limit();

		if ( wp_using_ext_object_cache() ) {
			$key = 'rate_' . $window;
			wp_cache_add( $key, 0, self::GROUP, 120 );
			$count = wp_cache_incr( $key, 1, self::GROUP );
			return false !== $count && $count <= $limit;
		}

		$state = get_transient( self::TRANSIENT );
		if ( ! is_array( $state ) || ! isset( $state['w'], $state['n'] ) || (int) $state['w'] !== $window ) {
			$state = array(
				'w' => $window,
				'n' => 0,
			);
		}
		if ( (int) $state['n'] >= $limit ) {
			return false;
		}
		++$state['n'];
		set_transient( self::TRANSIENT, $state, 120 );
		return true;
	}
}
