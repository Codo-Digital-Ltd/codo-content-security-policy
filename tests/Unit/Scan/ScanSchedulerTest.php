<?php
/**
 * Tests for ScanScheduler.
 *
 * @package CodoDigital\Csp\Tests
 */

namespace CodoDigital\Csp\Tests\Unit\Scan;

use Brain\Monkey\Functions;
use CodoDigital\Csp\Scan\ScanScheduler;
use CodoDigital\Csp\Scan\Scanner;
use CodoDigital\Csp\Settings\Settings;
use CodoDigital\Csp\Tests\TestCase;

class ScanSchedulerTest extends TestCase {

	/** @var \Mockery\MockInterface */
	private $scanner;

	/**
	 * Post meta written, by post ID and key.
	 *
	 * @var array<int, array<string, mixed>>
	 */
	private $meta = array();

	protected function setUp(): void {
		parent::setUp();
		$this->meta    = array();
		$this->scanner = \Mockery::mock( Scanner::class );
		Functions\when( 'update_post_meta' )->alias(
			function ( $id, $key, $value ) {
				$this->meta[ $id ][ $key ] = $value;
				return true;
			}
		);
	}

	private function scheduler( $scan_on_save = true ) {
		$this->options[ Settings::OPTION ] = array( 'scan_on_save' => $scan_on_save );
		return new ScanScheduler( new Settings(), $this->scanner );
	}

	private static function post( $id = 12, $type = 'post' ) {
		return (object) array(
			'ID'        => $id,
			'post_type' => $type,
		);
	}

	private static function result( $url, $status = 'ok' ) {
		return array(
			'url'    => $url,
			'status' => $status,
		);
	}

	private function stub_post_checks( $revision = false, $autosave = false, $viewable = true ) {
		Functions\when( 'wp_is_post_revision' )->justReturn( $revision );
		Functions\when( 'wp_is_post_autosave' )->justReturn( $autosave );
		Functions\when( 'is_post_type_viewable' )->justReturn( $viewable );
	}

	public function test_register_hooks() {
		$scheduler = $this->scheduler();
		$scheduler->register();
		$this->assertNotFalse( has_action( 'transition_post_status', array( $scheduler, 'on_transition' ) ) );
		$this->assertNotFalse( has_action( ScanScheduler::POST_HOOK, array( $scheduler, 'scan_post' ) ) );
		$this->assertNotFalse( has_action( ScanScheduler::BATCH_HOOK, array( $scheduler, 'run_batch' ) ) );
		$this->assertNotFalse( has_action( ScanScheduler::URL_HOOK, array( $scheduler, 'scan_url' ) ) );
	}

	public function test_on_transition_schedules_a_scan() {
		$this->stub_post_checks();
		Functions\expect( 'wp_next_scheduled' )->once()->with( ScanScheduler::POST_HOOK, array( 12 ) )->andReturn( false );
		Functions\expect( 'wp_schedule_single_event' )->once()->with(
			\Mockery::on(
				static function ( $time ) {
					return abs( $time - ( time() + 5 ) ) <= 2;
				}
			),
			ScanScheduler::POST_HOOK,
			array( 12 )
		);
		$this->scheduler()->on_transition( 'publish', 'draft', self::post( '12' ) );
	}

	public function test_on_transition_does_not_schedule_twice() {
		$this->stub_post_checks();
		Functions\when( 'wp_next_scheduled' )->justReturn( time() + 3 );
		Functions\expect( 'wp_schedule_single_event' )->never();
		$this->scheduler()->on_transition( 'publish', 'publish', self::post() );
	}

	/**
	 * @dataProvider ignored_transitions
	 */
	public function test_on_transition_guards( $scan_on_save, $new_status, $post ) {
		$this->stub_post_checks();
		Functions\expect( 'wp_next_scheduled' )->never();
		Functions\expect( 'wp_schedule_single_event' )->never();
		$this->scheduler( $scan_on_save )->on_transition( $new_status, 'draft', $post );
	}

	public function ignored_transitions() {
		return array(
			'setting off'   => array( false, 'publish', self::post() ),
			'not published' => array( true, 'draft', self::post() ),
			'trashed'       => array( true, 'trash', self::post() ),
			'not an object' => array( true, 'publish', 12 ),
			'no id'         => array( true, 'publish', self::post( 0 ) ),
		);
	}

	/**
	 * @dataProvider ignored_posts
	 */
	public function test_on_transition_skips_revisions_autosaves_and_hidden_types( $revision, $autosave, $viewable ) {
		$this->stub_post_checks( $revision, $autosave, $viewable );
		Functions\expect( 'wp_next_scheduled' )->never();
		Functions\expect( 'wp_schedule_single_event' )->never();
		$this->scheduler()->on_transition( 'publish', 'draft', self::post() );
	}

	public function ignored_posts() {
		return array(
			'revision'       => array( 11, false, true ),
			'autosave'       => array( false, 11, true ),
			'not viewable'   => array( false, false, false ),
		);
	}

	public function test_scan_post_stores_result_and_status() {
		Functions\expect( 'get_post_status' )->once()->with( 7 )->andReturn( 'publish' );
		Functions\expect( 'get_permalink' )->once()->with( 7 )->andReturn( 'https://www.example.com/hello/' );
		$result = self::result( 'https://www.example.com/hello/', 'issues' );
		$this->scanner->shouldReceive( 'scan' )->once()->with( 'https://www.example.com/hello/' )->andReturn( $result );

		$this->assertSame( $result, $this->scheduler()->scan_post( '7' ) );
		$this->assertSame(
			array(
				ScanScheduler::META        => $result,
				ScanScheduler::STATUS_META => 'issues',
			),
			$this->meta[7]
		);
	}

	public function test_scan_post_skips_unpublished() {
		Functions\when( 'get_post_status' )->justReturn( 'private' );
		Functions\expect( 'get_permalink' )->never();
		$this->scanner->shouldNotReceive( 'scan' );
		$this->assertNull( $this->scheduler()->scan_post( 7 ) );
		$this->assertSame( array(), $this->meta );
	}

	/**
	 * @dataProvider bad_permalinks
	 */
	public function test_scan_post_skips_missing_permalink( $permalink ) {
		Functions\when( 'get_post_status' )->justReturn( 'publish' );
		Functions\when( 'get_permalink' )->justReturn( $permalink );
		$this->scanner->shouldNotReceive( 'scan' );
		$this->assertNull( $this->scheduler()->scan_post( 7 ) );
	}

	public function bad_permalinks() {
		return array(
			'false' => array( false ),
			'empty' => array( '' ),
		);
	}

	public function test_scan_url_remembers_result() {
		$result = self::result( 'https://www.example.com/a/' );
		$this->scanner->shouldReceive( 'scan' )->once()->with( 'https://www.example.com/a/', null )->andReturn( $result );
		$scheduler = $this->scheduler();
		$this->assertSame( $result, $scheduler->scan_url( 'https://www.example.com/a/' ) );
		$this->assertSame( array( 'https://www.example.com/a/' => $result ), $scheduler->url_scans() );
	}

	public function test_scan_url_passes_the_context() {
		$result = self::result( 'https://www.example.com/secret-login/' );
		$this->scanner->shouldReceive( 'scan' )->once()->with( 'https://www.example.com/secret-login/', 'login' )->andReturn( $result );
		$this->assertSame( $result, $this->scheduler()->scan_url( 'https://www.example.com/secret-login/', 'login' ) );
	}

	public function test_remember_keeps_newest_first_without_duplicates() {
		$scheduler = $this->scheduler();
		$scheduler->remember( self::result( 'https://www.example.com/a/' ) );
		$scheduler->remember( self::result( 'https://www.example.com/b/' ) );
		$scheduler->remember( self::result( 'https://www.example.com/a/', 'issues' ) );

		$scans = $scheduler->url_scans();
		$this->assertSame( array( 'https://www.example.com/a/', 'https://www.example.com/b/' ), array_keys( $scans ) );
		$this->assertSame( 'issues', $scans['https://www.example.com/a/']['status'] );
	}

	public function test_remember_caps_list() {
		$scheduler = $this->scheduler();
		for ( $i = 0; $i < ScanScheduler::MAX_URLS + 5; $i++ ) {
			$scheduler->remember( self::result( 'https://www.example.com/p' . $i . '/' ) );
		}
		$scans = $scheduler->url_scans();
		$this->assertCount( ScanScheduler::MAX_URLS, $scans );
		$this->assertSame( 'https://www.example.com/p24/', array_key_first( $scans ) );
		$this->assertArrayNotHasKey( 'https://www.example.com/p4/', $scans );
		$this->assertArrayHasKey( 'https://www.example.com/p5/', $scans );
	}

	public function test_url_scans_tolerates_corrupt_option() {
		$scheduler                                  = $this->scheduler();
		$this->options[ ScanScheduler::URL_OPTION ] = 'garbage';
		$this->assertSame( array(), $scheduler->url_scans() );

		$scheduler->remember( self::result( 'https://www.example.com/a/' ) );
		$this->assertCount( 1, $scheduler->url_scans() );
	}

	public function test_forget() {
		$scheduler = $this->scheduler();
		$scheduler->remember( self::result( 'https://www.example.com/a/' ) );
		$scheduler->remember( self::result( 'https://www.example.com/b/' ) );
		$scheduler->forget( 'https://www.example.com/a/' );
		$scheduler->forget( 'https://www.example.com/missing/' );
		$this->assertSame( array( 'https://www.example.com/b/' ), array_keys( $scheduler->url_scans() ) );
	}

	public function test_queue_recent_with_nothing_published() {
		Functions\when( 'get_post_types' )->justReturn( array( 'post' => 'post' ) );
		Functions\when( 'is_post_type_viewable' )->justReturn( true );
		Functions\when( 'get_posts' )->justReturn( array() );
		Functions\expect( 'wp_schedule_single_event' )->never();
		$this->assertSame( 0, $this->scheduler()->queue_recent() );
	}

	public function test_queue_recent_with_non_array_result() {
		Functions\when( 'get_post_types' )->justReturn( array() );
		Functions\when( 'is_post_type_viewable' )->justReturn( true );
		Functions\when( 'get_posts' )->justReturn( null );
		Functions\expect( 'wp_schedule_single_event' )->never();
		$this->assertSame( 0, $this->scheduler()->queue_recent() );
	}

	public function test_queue_recent_queues_a_batch_of_viewable_types() {
		Functions\expect( 'get_post_types' )->once()->with( array( 'public' => true ) )->andReturn(
			array(
				'post'       => 'post',
				'page'       => 'page',
				'attachment' => 'attachment',
				'hidden'     => 'hidden',
			)
		);
		Functions\when( 'is_post_type_viewable' )->alias(
			static function ( $type ) {
				return 'hidden' !== $type;
			}
		);
		Functions\expect( 'get_posts' )->once()->with(
			\Mockery::on(
				static function ( $args ) {
					return array( 'post', 'page' ) === $args['post_type']
						&& 'publish' === $args['post_status']
						&& ScanScheduler::BATCH_LIMIT === $args['posts_per_page']
						&& 'modified' === $args['orderby']
						&& 'ids' === $args['fields'];
				}
			)
		)->andReturn( array( '3', 5, '8' ) );
		Functions\expect( 'wp_schedule_single_event' )->once()->with(
			\Mockery::type( 'int' ),
			ScanScheduler::BATCH_HOOK,
			array( array( 3, 5, 8 ) )
		);
		$this->assertSame( 3, $this->scheduler()->queue_recent() );
	}

	public function test_run_batch_scans_a_few_and_chains_the_rest() {
		Functions\when( 'get_post_status' )->justReturn( 'publish' );
		Functions\when( 'get_permalink' )->alias(
			static function ( $id ) {
				return 'https://www.example.com/?p=' . $id;
			}
		);
		$this->scanner->shouldReceive( 'scan' )->times( ScanScheduler::BATCH_SIZE )->andReturnUsing(
			static function ( $url ) {
				return array(
					'url'    => $url,
					'status' => 'ok',
				);
			}
		);
		Functions\expect( 'wp_schedule_single_event' )->once()->with(
			\Mockery::on(
				static function ( $time ) {
					return abs( $time - ( time() + 10 ) ) <= 2;
				}
			),
			ScanScheduler::BATCH_HOOK,
			array( array( 4, 5 ) )
		);

		$this->assertSame( 3, $this->scheduler()->run_batch( array( '1', 2, 3, 4, 5 ) ) );
		$this->assertSame( array( 1, 2, 3 ), array_keys( $this->meta ) );
	}

	public function test_run_batch_last_chunk_does_not_chain() {
		Functions\when( 'get_post_status' )->justReturn( 'draft' );
		Functions\expect( 'wp_schedule_single_event' )->never();
		$this->assertSame( 1, $this->scheduler()->run_batch( 9 ) );
		$this->assertSame( 0, $this->scheduler()->run_batch( array() ) );
	}

	public function test_flagged_posts() {
		Functions\expect( 'get_posts' )->once()->with(
			\Mockery::on(
				static function ( $args ) {
					return 10 === $args['posts_per_page']
						&& 'publish' === $args['post_status']
						&& 'ids' === $args['fields']
						&& array(
							array(
								'key'     => ScanScheduler::STATUS_META,
								'value'   => array( 'issues', 'error' ),
								'compare' => 'IN',
							),
						) === $args['meta_query'];
				}
			)
		)->andReturn( array( '4', 6 ) );
		$result = self::result( 'https://www.example.com/four/', 'issues' );
		Functions\when( 'get_post_meta' )->alias(
			static function ( $id, $key, $single ) use ( $result ) {
				return ScanScheduler::META === $key && true === $single && 4 === $id ? $result : '';
			}
		);
		Functions\when( 'get_the_title' )->alias(
			static function ( $id ) {
				return 'Post ' . $id;
			}
		);

		$this->assertSame(
			array(
				array(
					'id'     => 4,
					'title'  => 'Post 4',
					'result' => $result,
				),
			),
			$this->scheduler()->flagged_posts( '10' )
		);
	}

	public function test_flagged_posts_with_non_array_result() {
		Functions\when( 'get_posts' )->justReturn( false );
		$this->assertSame( array(), $this->scheduler()->flagged_posts() );
	}

	public function test_unschedule_clears_every_hook() {
		$cleared = array();
		Functions\when( 'wp_unschedule_hook' )->alias(
			static function ( $hook ) use ( &$cleared ) {
				$cleared[] = $hook;
			}
		);
		ScanScheduler::unschedule();
		$this->assertSame( array( ScanScheduler::POST_HOOK, ScanScheduler::BATCH_HOOK, ScanScheduler::URL_HOOK ), $cleared );
	}
}
