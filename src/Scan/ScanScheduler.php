<?php
/**
 * Runs scans in the background and stores their results.
 *
 * @package CodoDigital\Csp
 */

namespace CodoDigital\Csp\Scan;

use CodoDigital\Csp\Settings\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Scans published content after it is saved, on WP-Cron so saving is not
 * slowed down, and scans batches of recent content on request.
 */
class ScanScheduler {

	const POST_HOOK   = 'codo_csp_scan_post';
	const BATCH_HOOK  = 'codo_csp_scan_batch';
	const URL_HOOK    = 'codo_csp_scan_url';
	const META        = '_codo_csp_scan';
	const STATUS_META = '_codo_csp_scan_status';
	const URL_OPTION  = 'codo_csp_url_scans';
	const MAX_URLS    = 20;
	const BATCH_SIZE  = 3;
	const BATCH_LIMIT = 20;

	/**
	 * Settings.
	 *
	 * @var Settings
	 */
	private $settings;

	/**
	 * Scanner.
	 *
	 * @var Scanner
	 */
	private $scanner;

	/**
	 * Constructor.
	 *
	 * @param Settings $settings Settings.
	 * @param Scanner  $scanner  Scanner.
	 */
	public function __construct( Settings $settings, Scanner $scanner ) {
		$this->settings = $settings;
		$this->scanner  = $scanner;
	}

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function register() {
		add_action( 'transition_post_status', array( $this, 'on_transition' ), 10, 3 );
		add_action( self::POST_HOOK, array( $this, 'scan_post' ) );
		add_action( self::BATCH_HOOK, array( $this, 'run_batch' ) );
		add_action( self::URL_HOOK, array( $this, 'scan_url' ) );
	}

	/**
	 * Queue a scan when published content is saved.
	 *
	 * @param string   $new_status New status.
	 * @param string   $old_status Old status.
	 * @param \WP_Post $post       Post.
	 * @return void
	 */
	public function on_transition( $new_status, $old_status, $post ) {
		unset( $old_status );
		if ( ! $this->settings->get( 'scan_on_save' ) || 'publish' !== $new_status || ! is_object( $post ) || empty( $post->ID ) ) {
			return;
		}
		if ( wp_is_post_revision( $post->ID ) || wp_is_post_autosave( $post->ID ) || ! is_post_type_viewable( $post->post_type ) ) {
			return;
		}
		if ( ! wp_next_scheduled( self::POST_HOOK, array( (int) $post->ID ) ) ) {
			wp_schedule_single_event( time() + 5, self::POST_HOOK, array( (int) $post->ID ) );
		}
	}

	/**
	 * Scan one post and store the result on it.
	 *
	 * @param int $post_id Post ID.
	 * @return array<string, mixed>|null Result, or null when the post is not public.
	 */
	public function scan_post( $post_id ) {
		$post_id = (int) $post_id;
		if ( 'publish' !== get_post_status( $post_id ) ) {
			return null;
		}
		$url = get_permalink( $post_id );
		if ( ! is_string( $url ) || '' === $url ) {
			return null;
		}
		$result = $this->scanner->scan( $url );
		update_post_meta( $post_id, self::META, $result );
		update_post_meta( $post_id, self::STATUS_META, $result['status'] );
		return $result;
	}

	/**
	 * Scan a URL and keep the result in the recent scans list.
	 *
	 * @param string      $url     URL.
	 * @param string|null $context site or login; guessed from the URL when null.
	 * @return array<string, mixed>
	 */
	public function scan_url( $url, $context = null ) {
		$result = $this->scanner->scan( (string) $url, $context );
		$this->remember( $result );
		return $result;
	}

	/**
	 * Store a URL scan result (newest first, at most MAX_URLS).
	 *
	 * @param array<string, mixed> $result Result.
	 * @return void
	 */
	public function remember( array $result ) {
		$scans = $this->url_scans();
		unset( $scans[ $result['url'] ] );
		$scans = array( $result['url'] => $result ) + $scans;
		update_option( self::URL_OPTION, array_slice( $scans, 0, self::MAX_URLS, true ), false );
	}

	/**
	 * Recent URL scans, newest first.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public function url_scans() {
		$scans = get_option( self::URL_OPTION, array() );
		return is_array( $scans ) ? $scans : array();
	}

	/**
	 * Forget a URL scan.
	 *
	 * @param string $url URL.
	 * @return void
	 */
	public function forget( $url ) {
		$scans = $this->url_scans();
		unset( $scans[ $url ] );
		update_option( self::URL_OPTION, $scans, false );
	}

	/**
	 * Queue a scan of the most recent published content.
	 *
	 * @return int Items queued.
	 */
	public function queue_recent() {
		$types = array_values( array_filter( get_post_types( array( 'public' => true ) ), 'is_post_type_viewable' ) );
		$types = array_values( array_diff( $types, array( 'attachment' ) ) );
		$ids   = get_posts(
			array(
				'post_type'        => $types,
				'post_status'      => 'publish',
				'posts_per_page'   => self::BATCH_LIMIT,
				'orderby'          => 'modified',
				'order'            => 'DESC',
				'fields'           => 'ids',
				'no_found_rows'    => true,
				'suppress_filters' => false,
			)
		);
		$ids   = array_map( 'intval', is_array( $ids ) ? $ids : array() );
		if ( empty( $ids ) ) {
			return 0;
		}
		wp_schedule_single_event( time(), self::BATCH_HOOK, array( $ids ) );
		return count( $ids );
	}

	/**
	 * Scan a few posts, then queue the rest (so one cron run stays short).
	 *
	 * @param int[] $ids Post IDs.
	 * @return int Posts scanned.
	 */
	public function run_batch( $ids ) {
		$ids  = array_map( 'intval', (array) $ids );
		$now  = array_slice( $ids, 0, self::BATCH_SIZE );
		$rest = array_slice( $ids, self::BATCH_SIZE );
		foreach ( $now as $id ) {
			$this->scan_post( $id );
		}
		if ( ! empty( $rest ) ) {
			wp_schedule_single_event( time() + 10, self::BATCH_HOOK, array( $rest ) );
		}
		return count( $now );
	}

	/**
	 * Published posts whose last scan found problems or failed.
	 *
	 * @param int $limit Max posts.
	 * @return array<int, array{id: int, title: string, result: array<string, mixed>}>
	 */
	public function flagged_posts( $limit = 50 ) {
		$ids  = get_posts(
			array(
				'post_type'      => 'any',
				'post_status'    => 'publish',
				'posts_per_page' => (int) $limit,
				'fields'         => 'ids',
				'no_found_rows'  => true,
				// phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_query -- Admin screen only, small result.
				'meta_query'     => array(
					array(
						'key'     => self::STATUS_META,
						'value'   => array( 'issues', 'error' ),
						'compare' => 'IN',
					),
				),
			)
		);
		$list = array();
		foreach ( is_array( $ids ) ? $ids : array() as $id ) {
			$result = get_post_meta( (int) $id, self::META, true );
			if ( is_array( $result ) ) {
				$list[] = array(
					'id'     => (int) $id,
					'title'  => get_the_title( (int) $id ),
					'result' => $result,
				);
			}
		}
		return $list;
	}

	/**
	 * Clear scheduled scans (deactivation).
	 *
	 * @return void
	 */
	public static function unschedule() {
		foreach ( array( self::POST_HOOK, self::BATCH_HOOK, self::URL_HOOK ) as $hook ) {
			wp_unschedule_hook( $hook );
		}
	}
}
