<?php
/**
 * Aggregated storage for violation reports.
 *
 * @package CodoDigital\Csp
 */

namespace CodoDigital\Csp\Reports;

defined( 'ABSPATH' ) || exit;

/**
 * One row per unique (context, directive, blocked, disposition) with a hit
 * counter and the most recent page it happened on, not one row per report,
 * so one violation seen on every page of a large site is still one row.
 * When the table is full, reports about new violations are dropped and
 * counted, and the Reports tab says so (otherwise "no new reports" could be
 * mistaken for "nothing is blocked").
 */
class ReportRepository {

	const TABLE      = 'codo_csp_reports';
	const DB_VERSION = '1';
	const DB_OPTION  = 'codo_csp_db_version';
	const MAX_ROWS   = 500;
	const DROPPED    = 'codo_csp_reports_dropped';

	/**
	 * Database.
	 *
	 * @var \wpdb
	 */
	private $db;

	/**
	 * Constructor.
	 *
	 * @param \wpdb $db Database.
	 */
	public function __construct( $db ) {
		$this->db = $db;
	}

	/**
	 * Table name.
	 *
	 * @return string
	 */
	public function table() {
		return $this->db->prefix . self::TABLE;
	}

	/**
	 * Create or upgrade the table.
	 *
	 * @return void
	 */
	public function install() {
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset = $this->db->get_charset_collate();
		$sql     = "CREATE TABLE {$this->table()} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			fingerprint char(32) NOT NULL,
			context varchar(10) NOT NULL DEFAULT 'site',
			directive varchar(40) NOT NULL,
			blocked varchar(255) NOT NULL,
			document varchar(255) NOT NULL,
			disposition varchar(10) NOT NULL DEFAULT '',
			hits bigint(20) unsigned NOT NULL DEFAULT 1,
			first_seen datetime NOT NULL,
			last_seen datetime NOT NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY fingerprint (fingerprint),
			KEY last_seen (last_seen)
		) {$charset};";

		dbDelta( $sql );
		update_option( self::DB_OPTION, self::DB_VERSION, true );
	}

	/**
	 * Install when missing or outdated (each site of a network, lazily).
	 *
	 * @return void
	 */
	public function maybe_install() {
		if ( self::DB_VERSION !== get_option( self::DB_OPTION ) ) {
			$this->install();
		}
	}

	/**
	 * Record a report.
	 *
	 * @param array{directive: string, blocked: string, document: string, disposition: string, context?: string} $report Report.
	 * @param string|null                                                                                        $now    MySQL datetime (UTC).
	 * @return bool Whether it was stored or counted.
	 */
	public function record( array $report, $now = null ) {
		$now         = null === $now ? gmdate( 'Y-m-d H:i:s' ) : $now;
		$context     = isset( $report['context'] ) && 'login' === $report['context'] ? 'login' : 'site';
		$fingerprint = md5( $context . "\n" . $report['directive'] . "\n" . $report['blocked'] . "\n" . $report['disposition'] );
		$table       = $this->table();

		// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Own table; values prepared.
		$updated = $this->db->query(
			$this->db->prepare( "UPDATE {$table} SET hits = hits + 1, last_seen = %s, document = %s WHERE fingerprint = %s", $now, $report['document'], $fingerprint )
		);
		if ( $updated ) {
			return true;
		}

		if ( $this->count() >= $this->max_rows() ) {
			update_option( self::DROPPED, $this->dropped() + 1, false );
			return false;
		}

		$inserted = $this->db->query(
			$this->db->prepare(
				"INSERT INTO {$table} (fingerprint, context, directive, blocked, document, disposition, hits, first_seen, last_seen) VALUES (%s, %s, %s, %s, %s, %s, 1, %s, %s) ON DUPLICATE KEY UPDATE hits = hits + 1, last_seen = VALUES(last_seen), document = VALUES(document)",
				$fingerprint,
				$context,
				$report['directive'],
				$report['blocked'],
				$report['document'],
				$report['disposition'],
				$now,
				$now
			)
		);
		// phpcs:enable
		return (bool) $inserted;
	}

	/**
	 * Reports dropped because the table was full, since it was last cleared.
	 *
	 * @return int
	 */
	public function dropped() {
		return (int) get_option( self::DROPPED, 0 );
	}

	/**
	 * Row cap.
	 *
	 * @return int
	 */
	public function max_rows() {
		/**
		 * Filters how many unique violations are kept.
		 *
		 * @param int $max Rows.
		 */
		return max( 1, (int) apply_filters( 'codo_csp_max_report_rows', self::MAX_ROWS ) );
	}

	/**
	 * Number of rows.
	 *
	 * @return int
	 */
	public function count() {
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Own table, no input.
		return (int) $this->db->get_var( "SELECT COUNT(*) FROM {$this->table()}" );
	}

	/**
	 * A page of rows, most hits first.
	 *
	 * @param int $page     1-based page.
	 * @param int $per_page Rows per page.
	 * @return array<int, array<string, mixed>>
	 */
	public function page( $page, $per_page ) {
		$offset = max( 0, ( (int) $page - 1 ) * (int) $per_page );
		// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Own table; values prepared.
		$rows = $this->db->get_results(
			$this->db->prepare( "SELECT * FROM {$this->table()} ORDER BY hits DESC, last_seen DESC LIMIT %d OFFSET %d", (int) $per_page, $offset ),
			ARRAY_A
		);
		// phpcs:enable
		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * One row.
	 *
	 * @param int $id ID.
	 * @return array<string, mixed>|null
	 */
	public function find( $id ) {
		// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Own table; values prepared.
		$row = $this->db->get_row( $this->db->prepare( "SELECT * FROM {$this->table()} WHERE id = %d", (int) $id ), ARRAY_A );
		// phpcs:enable
		return is_array( $row ) ? $row : null;
	}

	/**
	 * Delete one row.
	 *
	 * @param int $id ID.
	 * @return void
	 */
	public function delete( $id ) {
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Own table.
		$this->db->delete( $this->table(), array( 'id' => (int) $id ), array( '%d' ) );
	}

	/**
	 * Delete everything.
	 *
	 * @return void
	 */
	public function clear() {
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Own table, no input.
		$this->db->query( "TRUNCATE TABLE {$this->table()}" );
		delete_option( self::DROPPED );
	}

	/**
	 * Delete rows not seen for a number of days.
	 *
	 * @param int $days Days.
	 * @return int Rows deleted.
	 */
	public function purge_older_than( $days ) {
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - max( 1, (int) $days ) * DAY_IN_SECONDS );
		// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Own table; values prepared.
		return (int) $this->db->query( $this->db->prepare( "DELETE FROM {$this->table()} WHERE last_seen < %s", $cutoff ) );
		// phpcs:enable
	}

	/**
	 * Drop the table (uninstall).
	 *
	 * @return void
	 */
	public function drop() {
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Own table, uninstall.
		$this->db->query( "DROP TABLE IF EXISTS {$this->table()}" );
		delete_option( self::DB_OPTION );
		delete_option( self::DROPPED );
	}
}
