<?php
/**
 * Tests for ReportRepository against a mocked wpdb.
 *
 * @package CodoDigital\Csp\Tests
 */

namespace CodoDigital\Csp\Tests\Unit\Reports;

use Brain\Monkey\Filters;
use Brain\Monkey\Functions;
use CodoDigital\Csp\Reports\ReportRepository;
use CodoDigital\Csp\Tests\TestCase;

class ReportRepositoryTest extends TestCase {

	/** @var \Mockery\MockInterface */
	private $db;

	/** @var array<int, array{sql: string, args: array<int, mixed>}> Calls to prepare(). */
	private $prepared = array();

	protected function setUp(): void {
		parent::setUp();
		$this->prepared   = array();
		$this->db         = \Mockery::mock( 'wpdb' );
		$this->db->prefix = 'wp_';
		$this->db->shouldReceive( 'prepare' )->andReturnUsing(
			function ( $sql, ...$args ) {
				$this->prepared[] = array(
					'sql'  => $sql,
					'args' => $args,
				);
				return 'PREPARED:' . $sql . '|' . implode( ',', $args );
			}
		);
	}

	private function repo() {
		return new ReportRepository( $this->db );
	}

	private function report() {
		return array(
			'directive'   => 'script-src-elem',
			'blocked'     => 'https://cdn.example.net',
			'document'    => '/shop/',
			'disposition' => 'report',
		);
	}

	private function fingerprint( $context = 'site' ) {
		return md5( $context . "\nscript-src-elem\nhttps://cdn.example.net\nreport" );
	}

	public function test_table_uses_site_prefix() {
		$this->assertSame( 'wp_codo_csp_reports', $this->repo()->table() );
	}

	public function test_install_runs_db_delta_and_records_version() {
		$this->db->shouldReceive( 'get_charset_collate' )->once()->andReturn( 'DEFAULT CHARSET=utf8mb4' );
		Functions\expect( 'dbDelta' )->once()->with(
			\Mockery::on(
				static function ( $sql ) {
					return false !== strpos( $sql, 'CREATE TABLE wp_codo_csp_reports' )
						&& false !== strpos( $sql, 'UNIQUE KEY fingerprint (fingerprint)' )
						&& false !== strpos( $sql, 'PRIMARY KEY  (id)' )
						&& false !== strpos( $sql, "context varchar(10) NOT NULL DEFAULT 'site'," )
						&& false !== strpos( $sql, ') DEFAULT CHARSET=utf8mb4;' );
				}
			)
		);

		$this->repo()->install();
		$this->assertSame( ReportRepository::DB_VERSION, $this->options[ ReportRepository::DB_OPTION ] );
	}

	public function test_maybe_install_skips_when_current() {
		$this->options[ ReportRepository::DB_OPTION ] = ReportRepository::DB_VERSION;
		Functions\expect( 'dbDelta' )->never();
		$this->db->shouldNotReceive( 'get_charset_collate' );
		$this->repo()->maybe_install();
		$this->assertSame( ReportRepository::DB_VERSION, $this->options[ ReportRepository::DB_OPTION ] );
	}

	public function test_maybe_install_runs_when_missing_or_outdated() {
		$this->db->shouldReceive( 'get_charset_collate' )->twice()->andReturn( '' );
		Functions\expect( 'dbDelta' )->twice();

		$this->repo()->maybe_install();
		$this->assertSame( ReportRepository::DB_VERSION, $this->options[ ReportRepository::DB_OPTION ] );

		$this->options[ ReportRepository::DB_OPTION ] = '0';
		$this->repo()->maybe_install();
		$this->assertSame( ReportRepository::DB_VERSION, $this->options[ ReportRepository::DB_OPTION ] );
	}

	public function test_record_counts_existing_row() {
		$this->db->shouldReceive( 'query' )->once()->with( \Mockery::pattern( '/^PREPARED:UPDATE wp_codo_csp_reports SET hits = hits \+ 1/' ) )->andReturn( 1 );
		$this->db->shouldNotReceive( 'get_var' );

		$this->assertTrue( $this->repo()->record( $this->report(), '2026-10-21 10:00:00' ) );
		$this->assertSame( array( '2026-10-21 10:00:00', '/shop/', $this->fingerprint() ), $this->prepared[0]['args'] );
		$this->assertStringContainsString( 'document = %s WHERE fingerprint = %s', $this->prepared[0]['sql'], 'the latest page is kept' );
	}

	public function test_fingerprint_ignores_the_page_but_not_the_context() {
		$this->db->shouldReceive( 'query' )->times( 4 )->andReturn( 1 );
		$repo  = $this->repo();
		$other = array_merge( $this->report(), array( 'document' => '/other/' ) );

		$repo->record( $this->report() );
		$repo->record( $other );
		$repo->record( array_merge( $this->report(), array( 'context' => 'login' ) ) );
		$repo->record( array_merge( $this->report(), array( 'context' => 'admin' ) ) );

		$this->assertSame( $this->fingerprint(), $this->prepared[0]['args'][2] );
		$this->assertSame( $this->fingerprint(), $this->prepared[1]['args'][2], 'same violation on another page is the same row' );
		$this->assertSame( $this->fingerprint( 'login' ), $this->prepared[2]['args'][2] );
		$this->assertNotSame( $this->fingerprint(), $this->fingerprint( 'login' ) );
		$this->assertSame( $this->fingerprint(), $this->prepared[3]['args'][2], 'unknown contexts count as site' );
	}

	public function test_record_inserts_new_row() {
		$this->db->shouldReceive( 'query' )->once()->with( \Mockery::pattern( '/^PREPARED:UPDATE /' ) )->andReturn( 0 );
		$this->db->shouldReceive( 'get_var' )->once()->with( 'SELECT COUNT(*) FROM wp_codo_csp_reports' )->andReturn( '3' );
		$this->db->shouldReceive( 'query' )->once()->with( \Mockery::pattern( '/^PREPARED:INSERT INTO wp_codo_csp_reports .*ON DUPLICATE KEY UPDATE/' ) )->andReturn( 1 );

		$this->assertTrue( $this->repo()->record( $this->report(), '2026-10-21 10:00:00' ) );
		$this->assertSame(
			array( $this->fingerprint(), 'site', 'script-src-elem', 'https://cdn.example.net', '/shop/', 'report', '2026-10-21 10:00:00', '2026-10-21 10:00:00' ),
			$this->prepared[1]['args']
		);
		$this->assertStringContainsString( '(fingerprint, context, directive, blocked, document, disposition, hits, first_seen, last_seen)', $this->prepared[1]['sql'] );
		$this->assertStringContainsString( 'document = VALUES(document)', $this->prepared[1]['sql'] );
	}

	public function test_record_inserts_login_context() {
		$this->db->shouldReceive( 'query' )->once()->with( \Mockery::pattern( '/^PREPARED:UPDATE /' ) )->andReturn( 0 );
		$this->db->shouldReceive( 'get_var' )->once()->andReturn( '0' );
		$this->db->shouldReceive( 'query' )->once()->with( \Mockery::pattern( '/^PREPARED:INSERT /' ) )->andReturn( 1 );

		$this->assertTrue( $this->repo()->record( array_merge( $this->report(), array( 'context' => 'login' ) ), '2026-10-21 10:00:00' ) );
		$this->assertSame( array( $this->fingerprint( 'login' ), 'login' ), array_slice( $this->prepared[1]['args'], 0, 2 ) );
	}

	public function test_record_defaults_to_current_utc_time() {
		$this->db->shouldReceive( 'query' )->once()->andReturn( 1 );
		$this->assertTrue( $this->repo()->record( $this->report() ) );
		$this->assertMatchesRegularExpression( '/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $this->prepared[0]['args'][0] );
	}

	public function test_record_reports_failed_insert() {
		$this->db->shouldReceive( 'query' )->twice()->andReturn( false, false );
		$this->db->shouldReceive( 'get_var' )->once()->andReturn( null );
		$this->assertFalse( $this->repo()->record( $this->report() ) );
	}

	public function test_record_refuses_new_rows_when_full() {
		$this->db->shouldReceive( 'query' )->once()->andReturn( 0 );
		$this->db->shouldReceive( 'get_var' )->once()->andReturn( (string) ReportRepository::MAX_ROWS );
		$this->assertSame( 0, $this->repo()->dropped() );
		$this->assertFalse( $this->repo()->record( $this->report() ) );
		$this->assertCount( 1, $this->prepared );
		$this->assertSame( 1, $this->repo()->dropped() );
	}

	public function test_dropped_reports_are_counted_without_autoload() {
		$this->options[ ReportRepository::DROPPED ] = '4';
		$this->db->shouldReceive( 'query' )->once()->andReturn( 0 );
		$this->db->shouldReceive( 'get_var' )->once()->andReturn( (string) ReportRepository::MAX_ROWS );
		$calls = array();
		Functions\when( 'update_option' )->alias(
			static function () use ( &$calls ) {
				$calls[] = func_get_args();
				return true;
			}
		);

		$this->assertFalse( $this->repo()->record( $this->report() ) );
		$this->assertSame( array( array( ReportRepository::DROPPED, 5, false ) ), $calls );
	}

	public function test_row_cap_is_filterable() {
		Filters\expectApplied( 'codo_csp_max_report_rows' )->once()->with( ReportRepository::MAX_ROWS )->andReturn( 2 );
		$this->db->shouldReceive( 'query' )->once()->andReturn( 0 );
		$this->db->shouldReceive( 'get_var' )->once()->andReturn( '2' );
		$this->assertFalse( $this->repo()->record( $this->report() ) );
	}

	public function test_max_rows_is_at_least_one() {
		$this->assertSame( ReportRepository::MAX_ROWS, $this->repo()->max_rows() );
		Filters\expectApplied( 'codo_csp_max_report_rows' )->andReturn( -5 );
		$this->assertSame( 1, $this->repo()->max_rows() );
	}

	public function test_count() {
		$this->db->shouldReceive( 'get_var' )->once()->andReturn( '7' );
		$this->assertSame( 7, $this->repo()->count() );
	}

	public function test_page_orders_and_offsets() {
		$rows = array( array( 'id' => '1' ) );
		$this->db->shouldReceive( 'get_results' )->once()->with( \Mockery::pattern( '/ORDER BY hits DESC, last_seen DESC LIMIT %d OFFSET %d\|25,50$/' ), ARRAY_A )->andReturn( $rows );
		$this->assertSame( $rows, $this->repo()->page( 3, 25 ) );
	}

	public function test_page_clamps_offset_and_handles_non_array() {
		$this->db->shouldReceive( 'get_results' )->once()->andReturn( null );
		$this->assertSame( array(), $this->repo()->page( 0, 10 ) );
		$this->assertSame( array( 10, 0 ), $this->prepared[0]['args'] );
	}

	public function test_find() {
		$row = array(
			'id'        => '4',
			'directive' => 'img-src',
		);
		$this->db->shouldReceive( 'get_row' )->once()->with( \Mockery::pattern( '/WHERE id = %d\|4$/' ), ARRAY_A )->andReturn( $row );
		$this->assertSame( $row, $this->repo()->find( '4' ) );
	}

	public function test_find_missing_returns_null() {
		$this->db->shouldReceive( 'get_row' )->once()->andReturn( null );
		$this->assertNull( $this->repo()->find( 99 ) );
	}

	public function test_delete() {
		$this->db->shouldReceive( 'delete' )->once()->with( 'wp_codo_csp_reports', array( 'id' => 5 ), array( '%d' ) );
		$this->repo()->delete( '5' );
	}

	public function test_clear_truncates() {
		$this->options[ ReportRepository::DROPPED ] = 3;
		$this->db->shouldReceive( 'query' )->once()->with( 'TRUNCATE TABLE wp_codo_csp_reports' );
		$this->repo()->clear();
		$this->assertArrayNotHasKey( ReportRepository::DROPPED, $this->options );
		$this->assertSame( 0, $this->repo()->dropped() );
	}

	public function test_purge_older_than() {
		$this->db->shouldReceive( 'query' )->once()->with( \Mockery::pattern( '/^PREPARED:DELETE FROM wp_codo_csp_reports WHERE last_seen < %s/' ) )->andReturn( 4 );
		$before = time();
		$this->assertSame( 4, $this->repo()->purge_older_than( 30 ) );
		$cutoff = strtotime( $this->prepared[0]['args'][0] . ' UTC' );
		$this->assertEqualsWithDelta( $before - 30 * DAY_IN_SECONDS, $cutoff, 2 );
	}

	public function test_purge_uses_at_least_one_day() {
		$this->db->shouldReceive( 'query' )->once()->andReturn( false );
		$before = time();
		$this->assertSame( 0, $this->repo()->purge_older_than( 0 ) );
		$cutoff = strtotime( $this->prepared[0]['args'][0] . ' UTC' );
		$this->assertEqualsWithDelta( $before - DAY_IN_SECONDS, $cutoff, 2 );
	}

	public function test_drop_removes_table_and_version() {
		$this->options[ ReportRepository::DB_OPTION ] = ReportRepository::DB_VERSION;
		$this->options[ ReportRepository::DROPPED ]   = 2;
		$this->db->shouldReceive( 'query' )->once()->with( 'DROP TABLE IF EXISTS wp_codo_csp_reports' );
		$this->repo()->drop();
		$this->assertArrayNotHasKey( ReportRepository::DB_OPTION, $this->options );
		$this->assertArrayNotHasKey( ReportRepository::DROPPED, $this->options );
	}
}
