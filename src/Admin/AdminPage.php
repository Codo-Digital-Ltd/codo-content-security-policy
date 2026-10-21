<?php
/**
 * Settings > Content Security Policy.
 *
 * @package CodoDigital\Csp
 */

namespace CodoDigital\Csp\Admin;

use CodoDigital\Csp\Http\HeaderSender;
use CodoDigital\Csp\Policy\Directives;
use CodoDigital\Csp\Policy\Policy;
use CodoDigital\Csp\Reports\ReportRepository;
use CodoDigital\Csp\Scan\ScanScheduler;
use CodoDigital\Csp\Settings\PolicyStore;
use CodoDigital\Csp\Settings\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * The site's admin screen. Server-rendered; no scripts are enqueued, so it
 * cannot clash with other plugins' admin JavaScript.
 */
class AdminPage {

	const SLUG       = 'codo-csp';
	const PER_PAGE   = 25;
	const STYLE      = 'codo-csp-admin';
	const SIZE_LIMIT = 4096;

	/**
	 * Settings.
	 *
	 * @var Settings
	 */
	private $settings;

	/**
	 * Policies.
	 *
	 * @var PolicyStore
	 */
	private $store;

	/**
	 * Reports.
	 *
	 * @var ReportRepository
	 */
	private $reports;

	/**
	 * Scans.
	 *
	 * @var ScanScheduler
	 */
	private $scheduler;

	/**
	 * Notices.
	 *
	 * @var Notices
	 */
	private $notices;

	/**
	 * Headers.
	 *
	 * @var HeaderSender
	 */
	private $headers;

	/**
	 * Policy renderer.
	 *
	 * @var PolicyView
	 */
	private $view;

	/**
	 * Constructor.
	 *
	 * @param Settings         $settings  Settings.
	 * @param PolicyStore      $store     Policies.
	 * @param ReportRepository $reports   Reports.
	 * @param ScanScheduler    $scheduler Scans.
	 * @param Notices          $notices   Notices.
	 * @param HeaderSender     $headers   Headers.
	 */
	public function __construct( Settings $settings, PolicyStore $store, ReportRepository $reports, ScanScheduler $scheduler, Notices $notices, HeaderSender $headers ) {
		$this->settings  = $settings;
		$this->store     = $store;
		$this->reports   = $reports;
		$this->scheduler = $scheduler;
		$this->notices   = $notices;
		$this->headers   = $headers;
		$this->view      = new PolicyView( $store );
	}

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function register() {
		add_action( 'admin_menu', array( $this, 'add_menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( CODO_CSP_FILE ), array( $this, 'action_links' ) );
	}

	/**
	 * Add the menu item.
	 *
	 * @return void
	 */
	public function add_menu() {
		add_options_page(
			__( 'Content Security Policy', 'codo-content-security-policy' ),
			__( 'Content Security Policy', 'codo-content-security-policy' ),
			Capability::site(),
			self::SLUG,
			array( $this, 'render' )
		);
	}

	/**
	 * Settings link on the Plugins screen.
	 *
	 * @param string[] $links Links.
	 * @return string[]
	 */
	public function action_links( $links ) {
		array_unshift( $links, '<a href="' . esc_url( $this->url() ) . '">' . esc_html__( 'Settings', 'codo-content-security-policy' ) . '</a>' );
		return $links;
	}

	/**
	 * Inline styles, on this screen only.
	 *
	 * @param string $hook Screen hook.
	 * @return void
	 */
	public function enqueue( $hook ) {
		if ( 'settings_page_' . self::SLUG !== $hook && 'settings_page_' . NetworkPage::SLUG !== $hook ) {
			return;
		}
		wp_register_style( self::STYLE, false, array(), CODO_CSP_VERSION );
		wp_enqueue_style( self::STYLE );
		wp_add_inline_style( self::STYLE, self::css() );
	}

	/**
	 * Screen styles.
	 *
	 * @return string
	 */
	public static function css() {
		return '.codo-csp-inline{display:inline}'
			. '.codo-csp-status{display:flex;flex-wrap:wrap;gap:8px 16px;align-items:center;margin:16px 0;padding:12px 16px;background:#fff;border:1px solid #c3c4c7;border-left-width:4px}'
			. '.codo-csp-status.is-report-only{border-left-color:#dba617}.codo-csp-status.is-enforced{border-left-color:#00a32a}.codo-csp-status.is-disabled{border-left-color:#d63638}'
			. '.codo-csp-rules th[scope=rowgroup]{width:22%;vertical-align:top}.codo-csp-rules code{word-break:break-all}'
			. '.codo-csp-pending-add td{background:#f0f6e9}.codo-csp-pending-remove td code{text-decoration:line-through}'
			. '.codo-csp-badge{display:inline-block;padding:0 6px;border-radius:3px;background:#f0f0f1;font-size:12px}'
			. '.codo-csp-changes{margin-left:1.5em;list-style:none}.codo-csp-add{color:#00a32a;font-weight:600}.codo-csp-remove{color:#d63638;font-weight:600}'
			. '.codo-csp-header{white-space:pre-wrap;word-break:break-all;background:#f6f7f7;padding:8px;display:block}'
			. '.codo-csp-scan summary{cursor:pointer;padding:8px 0}.codo-csp-scan{border-bottom:1px solid #dcdcde}'
			. '.codo-csp-ok{color:#00a32a}.codo-csp-bad{color:#d63638}';
	}

	/**
	 * URL of a tab.
	 *
	 * @param string               $tab  Tab.
	 * @param array<string, mixed> $args Extra args.
	 * @return string
	 */
	public function url( $tab = 'policy', array $args = array() ) {
		return add_query_arg( array_merge( array( 'tab' => $tab ), $args ), admin_url( 'options-general.php?page=' . self::SLUG ) );
	}

	/**
	 * Tabs.
	 *
	 * @return array<string, string>
	 */
	public function tabs() {
		$tabs = array( 'policy' => __( 'Policy', 'codo-content-security-policy' ) );
		if ( $this->settings->get( 'login_enabled' ) ) {
			$tabs['login'] = __( 'Login page', 'codo-content-security-policy' );
		}
		$tabs['reports']  = __( 'Reports', 'codo-content-security-policy' );
		$tabs['scan']     = __( 'Scan', 'codo-content-security-policy' );
		$tabs['settings'] = __( 'Settings', 'codo-content-security-policy' );
		return $tabs;
	}

	/**
	 * Current tab.
	 *
	 * @return string
	 */
	private function current_tab() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Navigation only.
		$tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'policy';
		return array_key_exists( $tab, $this->tabs() ) ? $tab : 'policy';
	}

	/**
	 * Render the screen.
	 *
	 * @return void
	 */
	public function render() {
		if ( ! current_user_can( Capability::site() ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'codo-content-security-policy' ), 403 );
		}
		$tab = $this->current_tab();

		echo '<div class="wrap codo-csp"><h1>' . esc_html__( 'Content Security Policy', 'codo-content-security-policy' ) . '</h1>';
		$this->notices->render();
		$this->render_status( $tab );

		echo '<nav class="nav-tab-wrapper" aria-label="' . esc_attr__( 'Sections', 'codo-content-security-policy' ) . '">';
		foreach ( $this->tabs() as $slug => $label ) {
			printf(
				'<a href="%1$s" class="nav-tab%2$s"%3$s>%4$s</a>',
				esc_url( $this->url( $slug ) ),
				$slug === $tab ? ' nav-tab-active' : '',
				$slug === $tab ? ' aria-current="page"' : '',
				esc_html( $label )
			);
		}
		echo '</nav>';

		switch ( $tab ) {
			case 'login':
				$this->render_policy_tab( 'login' );
				break;
			case 'reports':
				$this->render_reports_tab();
				break;
			case 'scan':
				$this->render_scan_tab();
				break;
			case 'settings':
				$this->render_settings_tab();
				break;
			default:
				$this->render_policy_tab( 'site' );
		}
		echo '</div>';
	}

	/**
	 * Mode and reporting status, with the mode switch.
	 *
	 * @param string $tab Current tab (to return to).
	 * @return void
	 */
	private function render_status( $tab ) {
		if ( $this->settings->is_disabled() ) {
			echo '<div class="codo-csp-status is-disabled"><strong>' . esc_html__( 'Disabled by CODO_CSP_DISABLE in wp-config.php: no policy headers are sent.', 'codo-content-security-policy' ) . '</strong></div>';
			return;
		}

		$enforcing = $this->settings->is_enforcing();
		echo '<div class="codo-csp-status ' . esc_attr( $enforcing ? 'is-enforced' : 'is-report-only' ) . '"><div><strong>';
		echo esc_html( $enforcing ? __( 'Enforced', 'codo-content-security-policy' ) : __( 'Report-Only', 'codo-content-security-policy' ) );
		echo '</strong> &mdash; ';
		echo esc_html(
			$enforcing
				? __( 'browsers block anything the policy does not allow. The admin area is never covered, so you can always get back here.', 'codo-content-security-policy' )
				: __( 'nothing is blocked. Browsers report what the policy would block, so you can build it up safely.', 'codo-content-security-policy' )
		);
		echo '</div><div>';

		if ( $this->settings->is_locked( 'mode' ) ) {
			echo '<span class="description">' . esc_html__( 'Set by CODO_CSP_MODE in wp-config.php.', 'codo-content-security-policy' ) . '</span>';
		} elseif ( $enforcing ) {
			PolicyView::button(
				'mode',
				'site',
				'site',
				array(
					'mode'   => Settings::MODE_REPORT_ONLY,
					'return' => $tab,
				),
				__( 'Switch to Report-Only', 'codo-content-security-policy' ),
				'button'
			);
		} else {
			PolicyView::button(
				'mode',
				'site',
				'site',
				array(
					'mode'   => Settings::MODE_ENFORCE,
					'return' => $tab,
				),
				__( 'Enforce the policy', 'codo-content-security-policy' ),
				'button button-primary'
			);
		}
		echo '</div><div class="description">' . esc_html( $this->reporting_summary() ) . '</div></div>';
	}

	/**
	 * One line about where reports go.
	 *
	 * @return string
	 */
	private function reporting_summary() {
		if ( Settings::REPORTING_EXTERNAL === $this->settings->get( 'reporting' ) ) {
			/* translators: %s: URL. */
			return sprintf( __( 'Reports go to %s.', 'codo-content-security-policy' ), (string) $this->settings->get( 'external_uri' ) );
		}
		if ( $this->settings->is_collecting() ) {
			return sprintf(
				/* translators: %s: date and time. */
				__( 'Collecting reports until %s.', 'codo-content-security-policy' ),
				wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $this->settings->get( 'report_until' ) )
			);
		}
		return __( 'Not collecting reports.', 'codo-content-security-policy' );
	}

	/**
	 * Policy tab for a context.
	 *
	 * @param string $context site or login.
	 * @return void
	 */
	private function render_policy_tab( $context ) {
		if ( 'login' === $context ) {
			echo '<p>' . esc_html__( 'wp-login.php has its own policy, because login security plugins (reCAPTCHA, Turnstile, two-factor) load scripts there that the rest of the site does not need.', 'codo-content-security-policy' ) . '</p>';
		} else {
			echo '<p>' . esc_html__( 'Sent on every front-end page, for visitors and logged-in users alike. Not sent in wp-admin, or inside page builders and the Customizer preview.', 'codo-content-security-policy' ) . '</p>';
		}
		if ( is_multisite() ) {
			echo '<p class="description">' . esc_html__( 'Network defaults are set by the network administrator and apply to every site.', 'codo-content-security-policy' ) . '</p>';
		}
		$this->view->render( $context, 'site' );
		$this->render_header_preview( $context );
	}

	/**
	 * The headers as they are sent now.
	 *
	 * @param string $context Context.
	 * @return void
	 */
	private function render_header_preview( $context ) {
		echo '<h2>' . esc_html__( 'Headers sent', 'codo-content-security-policy' ) . '</h2>';
		$headers = $this->headers->build( $context );
		if ( empty( $headers ) ) {
			echo '<p>' . esc_html__( 'None.', 'codo-content-security-policy' ) . '</p>';
			return;
		}
		$size = 0;
		foreach ( $headers as $name => $values ) {
			foreach ( $values as $value ) {
				$size += strlen( $name ) + strlen( $value ) + 4;
				echo '<p><strong>' . esc_html( $name ) . '</strong><code class="codo-csp-header">' . esc_html( $value ) . '</code></p>';
			}
		}
		/* translators: %s: size such as 1.2 KB. */
		echo '<p class="description">' . esc_html( sprintf( __( 'Total size: %s.', 'codo-content-security-policy' ), size_format( $size, 1 ) ) ) . '</p>';
		if ( $size > self::SIZE_LIMIT ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'The headers are over 4 KB. NGINX with default FastCGI buffers can fail with "upstream sent too big header" (502). Remove sources you no longer need, or raise fastcgi_buffer_size.', 'codo-content-security-policy' ) . '</p></div>';
		}
	}

	/**
	 * Reports tab.
	 *
	 * @return void
	 */
	private function render_reports_tab() {
		$reporting = $this->settings->get( 'reporting' );
		echo '<p>' . esc_html__( 'Browsers report what the policy blocks (or would block, in Report-Only). Identical reports are counted, not stored again; at most 500 different ones are kept, for 30 days. No IP addresses, user agents or full URLs are stored.', 'codo-content-security-policy' ) . '</p>';
		echo '<p>' . esc_html__( 'Anyone can send a report, so treat them as suggestions: only allow sources you recognise. Sources a scan also found are marked.', 'codo-content-security-policy' ) . '</p>';

		if ( Settings::REPORTING_EXTERNAL === $reporting ) {
			/* translators: %s: URL. */
			echo '<p>' . esc_html( sprintf( __( 'Reports are sent to %s, so none are collected here.', 'codo-content-security-policy' ), (string) $this->settings->get( 'external_uri' ) ) ) . '</p>';
		} else {
			echo '<p>';
			if ( $this->settings->is_collecting() ) {
				echo esc_html( $this->reporting_summary() ) . ' ';
				PolicyView::button( 'reporting', 'site', 'site', array( 'op' => 'stop' ), __( 'Stop collecting', 'codo-content-security-policy' ), 'button' );
			} else {
				foreach ( Settings::REPORT_WINDOWS as $days ) {
					PolicyView::button(
						'reporting',
						'site',
						'site',
						array(
							'op'   => 'start',
							'days' => $days,
						),
						/* translators: %d: number of days. */
						sprintf( _n( 'Collect for %d day', 'Collect for %d days', $days, 'codo-content-security-policy' ), $days ),
						'button'
					);
					echo ' ';
				}
			}
			echo '</p>';
		}

		$dropped = $this->reports->dropped();
		if ( $dropped > 0 ) {
			echo '<div class="notice notice-error inline"><p><strong>' . esc_html(
				sprintf(
					/* translators: %s: number of reports. */
					_n( 'The report table is full: %s report about a new violation was dropped.', 'The report table is full: %s reports about new violations were dropped.', $dropped, 'codo-content-security-policy' ),
					number_format_i18n( $dropped )
				)
			) . '</strong> ' . esc_html__( 'Until you clear the reports, a quiet Reports tab does not mean nothing is blocked. Clear them before enforcing or promoting a draft.', 'codo-content-security-policy' ) . '</p></div>';
		}

		$total = $this->reports->count();
		if ( 0 === $total ) {
			echo '<p><em>' . esc_html__( 'No reports.', 'codo-content-security-policy' ) . '</em></p>';
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Pagination only.
		$page  = isset( $_GET['paged'] ) ? max( 1, absint( $_GET['paged'] ) ) : 1;
		$rows  = $this->reports->page( $page, self::PER_PAGE );
		$found = $this->scanned_sources();

		echo '<table class="widefat striped"><thead><tr>';
		foreach ( array( __( 'Directive', 'codo-content-security-policy' ), __( 'Blocked', 'codo-content-security-policy' ), __( 'Latest page', 'codo-content-security-policy' ), __( 'Count', 'codo-content-security-policy' ), __( 'Last seen', 'codo-content-security-policy' ), __( 'Status', 'codo-content-security-policy' ), '' ) as $heading ) {
			echo '<th scope="col">' . esc_html( $heading ) . '</th>';
		}
		echo '</tr></thead><tbody>';
		foreach ( $rows as $row ) {
			$this->render_report_row( $row, $found );
		}
		echo '</tbody></table>';

		$pages = (int) ceil( $total / self::PER_PAGE );
		if ( $pages > 1 ) {
			echo '<p class="tablenav-pages">';
			for ( $i = 1; $i <= $pages; $i++ ) {
				if ( $i === $page ) {
					echo '<strong>' . esc_html( (string) $i ) . '</strong> ';
				} else {
					echo '<a href="' . esc_url( $this->url( 'reports', array( 'paged' => $i ) ) ) . '">' . esc_html( (string) $i ) . '</a> ';
				}
			}
			echo '</p>';
		}

		echo '<p>';
		PolicyView::button( 'clear_reports', 'site', 'site', array(), __( 'Clear all reports', 'codo-content-security-policy' ), 'button' );
		echo '</p>';
	}

	/**
	 * One report row.
	 *
	 * @param array<string, mixed> $row   Row.
	 * @param array<string, bool>  $found Sources found by scans ("directive source").
	 * @return void
	 */
	private function render_report_row( array $row, array $found ) {
		$suggestion = FormHandler::suggest_from_report( $row, $this->store );
		$context    = null !== $suggestion ? $suggestion['context'] : 'site';
		$live       = $this->store->live( $context );
		$allowed    = $this->report_allowed( $live, $row );

		if ( 'enforce' === $row['disposition'] ) {
			$status = __( 'Blocked', 'codo-content-security-policy' );
		} elseif ( ! $this->settings->is_enforcing() ) {
			$status = __( 'Would be blocked', 'codo-content-security-policy' );
		} elseif ( null !== $this->store->draft( $context ) ) {
			$status = __( 'Would be blocked by the draft', 'codo-content-security-policy' );
		} else {
			$status = __( 'Reported while in Report-Only', 'codo-content-security-policy' );
		}

		echo '<tr><td><code>' . esc_html( (string) $row['directive'] ) . '</code>';
		if ( 'login' === $context ) {
			echo ' <span class="codo-csp-badge">' . esc_html__( 'login page', 'codo-content-security-policy' ) . '</span>';
		}
		echo '</td>';
		echo '<td><code>' . esc_html( (string) $row['blocked'] ) . '</code>';
		if ( null !== $suggestion && isset( $found[ $suggestion['directive'] . ' ' . $suggestion['source'] ] ) ) {
			echo ' <span class="codo-csp-badge">' . esc_html__( 'also found by a scan', 'codo-content-security-policy' ) . '</span>';
		}
		echo '</td><td>' . esc_html( (string) $row['document'] ) . '</td>';
		echo '<td>' . esc_html( number_format_i18n( (int) $row['hits'] ) ) . '</td>';
		echo '<td>' . esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) strtotime( $row['last_seen'] . ' UTC' ) ) ) . '</td>';
		echo '<td>' . esc_html( $allowed ? __( 'Allowed now', 'codo-content-security-policy' ) : $status ) . '</td><td>';

		if ( ! $allowed && null !== $suggestion ) {
			PolicyView::button(
				'allow_report',
				$context,
				'site',
				array( 'id' => (int) $row['id'] ),
				/* translators: 1: source, 2: directive. */
				sprintf( __( 'Allow %1$s in %2$s', 'codo-content-security-policy' ), $suggestion['source'], $suggestion['directive'] )
			);
			if ( in_array( $suggestion['source'], array( "'unsafe-inline'", "'unsafe-eval'" ), true ) ) {
				echo '<p class="description">' . esc_html__( 'This weakens the policy. Prefer fixing the code that needs it.', 'codo-content-security-policy' ) . '</p>';
			}
		}
		echo '</td></tr>';
	}

	/**
	 * Whether the live policy now allows what a report blocked.
	 *
	 * @param Policy               $live Live policy.
	 * @param array<string, mixed> $row  Report row.
	 * @return bool
	 */
	private function report_allowed( Policy $live, array $row ) {
		$directive = (string) $row['directive'];
		$blocked   = (string) $row['blocked'];
		if ( ! Directives::is_known( $directive ) ) {
			return false;
		}
		if ( 'inline' === $blocked ) {
			return $live->allows_inline( $directive );
		}
		if ( 'eval' === $blocked ) {
			$sources = $live->effective( $directive );
			return null === $sources || in_array( "'unsafe-eval'", $sources, true );
		}
		if ( 'wasm-eval' === $blocked ) {
			// 'unsafe-eval' also allows WebAssembly compilation.
			$sources = $live->effective( $directive );
			return null === $sources || array() !== array_intersect( array( "'wasm-unsafe-eval'", "'unsafe-eval'" ), $sources );
		}
		if ( in_array( $blocked, array( 'data:', 'blob:' ), true ) ) {
			return $live->allows( $directive, $blocked, home_url( '/' ) );
		}
		if ( false === strpos( $blocked, '//' ) ) {
			return false;
		}
		return $live->allows( $directive, $blocked . '/', (string) \CodoDigital\Csp\Policy\Source::origin_of( home_url( '/' ) ) );
	}

	/**
	 * Sources that scans have found, as "directive source" keys.
	 *
	 * @return array<string, bool>
	 */
	private function scanned_sources() {
		$found   = array();
		$results = array_values( $this->scheduler->url_scans() );
		foreach ( $this->scheduler->flagged_posts() as $post ) {
			$results[] = $post['result'];
		}
		foreach ( $results as $result ) {
			foreach ( array_merge( (array) $result['issues'], (array) $result['draft'] ) as $issue ) {
				$found[ $issue['target'] . ' ' . $issue['source'] ] = true;
			}
		}
		return $found;
	}

	/**
	 * Scan tab.
	 *
	 * @return void
	 */
	private function render_scan_tab() {
		echo '<p>' . esc_html__( 'A scan fetches a page as a logged-out visitor and checks every script, stylesheet, font, image, frame, media file and form target it finds (including fonts and images inside its stylesheets) against the policy. Published content is scanned automatically after it is saved.', 'codo-content-security-policy' ) . '</p>';
		echo '<p class="description">' . esc_html__( 'Resources added later by JavaScript (tag managers, chat widgets, ads) cannot be seen by a scan. Violation reports catch those.', 'codo-content-security-policy' ) . '</p>';

		PolicyView::open_form();
		PolicyView::hidden( 'scan', 'site', 'site', array( 'op' => 'url' ) );
		echo '<p><label for="codo-csp-scan-url">' . esc_html__( 'Page on this site', 'codo-content-security-policy' ) . '</label><br>';
		echo '<input type="url" class="regular-text code" id="codo-csp-scan-url" name="url" value="' . esc_attr( home_url( '/' ) ) . '" required> ';
		submit_button( __( 'Scan now', 'codo-content-security-policy' ), 'primary', 'submit', false );
		echo '</p></form><p>';
		if ( $this->settings->get( 'login_enabled' ) ) {
			PolicyView::button( 'scan', 'login', 'site', array( 'op' => 'login' ), __( 'Scan the login page', 'codo-content-security-policy' ), 'button' );
			echo ' ';
		}
		PolicyView::button( 'scan', 'site', 'site', array( 'op' => 'recent' ), __( 'Scan the 20 most recently updated pages', 'codo-content-security-policy' ), 'button' );
		echo '</p>';

		$scans = $this->scheduler->url_scans();
		if ( ! empty( $scans ) ) {
			echo '<h2>' . esc_html__( 'Recent scans', 'codo-content-security-policy' ) . '</h2>';
			foreach ( $scans as $result ) {
				$this->render_scan_result( $result, (string) $result['url'], true );
			}
		}

		$flagged = $this->scheduler->flagged_posts();
		echo '<h2>' . esc_html__( 'Published content with problems', 'codo-content-security-policy' ) . '</h2>';
		if ( empty( $flagged ) ) {
			echo '<p><em>' . esc_html__( 'None found by the latest scans.', 'codo-content-security-policy' ) . '</em></p>';
		}
		foreach ( $flagged as $post ) {
			$this->render_scan_result( $post['result'], '' !== $post['title'] ? $post['title'] : (string) $post['result']['url'], false );
		}
	}

	/**
	 * One scan result.
	 *
	 * @param array<string, mixed> $result Result.
	 * @param string               $label  Label.
	 * @param bool                 $forget Offer to remove it from the list.
	 * @return void
	 */
	public function render_scan_result( array $result, $label, $forget ) {
		$context = 'login' === $result['context'] ? 'login' : 'site';
		$open    = 'ok' !== $result['status'] ? ' open' : '';
		echo '<details class="codo-csp-scan"' . esc_attr( $open ) . '><summary>';
		if ( 'ok' === $result['status'] ) {
			echo '<span class="codo-csp-ok">&#10003;</span> ';
		} else {
			echo '<span class="codo-csp-bad">&#9888;</span> ';
		}
		echo '<strong>' . esc_html( $label ) . '</strong> <span class="description">' . esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $result['time'] ) ) . '</span></summary>';

		echo '<p><a href="' . esc_url( (string) $result['url'] ) . '">' . esc_html( (string) $result['url'] ) . '</a></p>';
		if ( '' !== $result['error'] ) {
			echo '<div class="notice notice-error inline"><p>' . esc_html( (string) $result['error'] ) . '</p></div>';
		}
		foreach ( (array) $result['warnings'] as $warning ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html( (string) $warning ) . '</p></div>';
		}
		if ( 'ok' === $result['status'] ) {
			/* translators: %d: number of resources. */
			echo '<p>' . esc_html( sprintf( __( 'All %d resources found are allowed.', 'codo-content-security-policy' ), (int) $result['checked'] ) ) . '</p>';
		}
		$this->render_issues( (array) $result['issues'], $context, __( 'Not allowed by the live policy', 'codo-content-security-policy' ) );
		$this->render_issues( (array) $result['draft'], $context, __( 'Not allowed by the draft', 'codo-content-security-policy' ) );
		if ( $forget ) {
			echo '<p>';
			PolicyView::button(
				'scan',
				'site',
				'site',
				array(
					'op'  => 'forget',
					'url' => (string) $result['url'],
				),
				__( 'Remove from list', 'codo-content-security-policy' ),
				'button-link'
			);
			echo '</p>';
		}
		echo '</details>';
	}

	/**
	 * A table of scan issues with Allow buttons.
	 *
	 * @param array<int, array<string, mixed>> $issues  Issues.
	 * @param string                           $context Context.
	 * @param string                           $caption Caption.
	 * @return void
	 */
	private function render_issues( array $issues, $context, $caption ) {
		if ( empty( $issues ) ) {
			return;
		}
		$live = $this->store->live( $context );
		echo '<table class="widefat striped"><caption class="screen-reader-text">' . esc_html( $caption ) . '</caption><thead><tr><th colspan="4">' . esc_html( $caption ) . '</th></tr></thead><tbody>';
		foreach ( $issues as $issue ) {
			$allowed = $live->has( (string) $issue['target'], (string) $issue['source'] );
			echo '<tr><td><code>' . esc_html( (string) $issue['directive'] ) . '</code></td><td>';
			if ( ! empty( $issue['inline'] ) ) {
				echo esc_html(
					sprintf(
						/* translators: %d: count. */
						_n( '%d inline block', '%d inline blocks', (int) $issue['count'], 'codo-content-security-policy' ),
						(int) $issue['count']
					)
				);
			} else {
				echo '<code>' . esc_html( (string) $issue['source'] ) . '</code><br><span class="description">' . esc_html( (string) $issue['example'] ) . '</span>';
			}
			echo '</td><td>' . esc_html( number_format_i18n( (int) $issue['count'] ) ) . '</td><td>';
			if ( $allowed ) {
				echo esc_html__( 'Allowed now', 'codo-content-security-policy' );
			} else {
				PolicyView::button(
					'add_rule',
					$context,
					'site',
					array(
						'directive' => (string) $issue['target'],
						'source'    => (string) $issue['source'],
						'origin'    => 'scan',
						'return'    => 'scan',
					),
					/* translators: 1: source, 2: directive. */
					sprintf( __( 'Allow %1$s in %2$s', 'codo-content-security-policy' ), (string) $issue['source'], (string) $issue['target'] )
				);
			}
			echo '</td></tr>';
		}
		echo '</tbody></table>';
	}

	/**
	 * Settings tab.
	 *
	 * @return void
	 */
	private function render_settings_tab() {
		PolicyView::open_form();
		PolicyView::hidden( 'settings', 'site', 'site' );
		echo '<table class="form-table" role="presentation"><tbody>';

		$this->checkbox_row( 'login_enabled', __( 'Login page', 'codo-content-security-policy' ), __( 'Send a policy on wp-login.php (it has its own rules on the Login page tab).', 'codo-content-security-policy' ) );
		$this->checkbox_row( 'skip_builders', __( 'Page builders', 'codo-content-security-policy' ), __( 'Leave out the policy in the Customizer preview and in front-end page builders (Elementor, Divi, Beaver Builder, Bricks, Oxygen, WPBakery, Thrive, Brizy, Avada) for users who can edit. Their editors inject inline code that an enforced policy would block.', 'codo-content-security-policy' ) );
		$this->checkbox_row( 'upgrade_insecure', __( 'Upgrade insecure requests', 'codo-content-security-policy' ), __( 'Ask browsers to load http:// resources over https:// (only when enforced; browsers ignore it in Report-Only).', 'codo-content-security-policy' ) );
		$this->checkbox_row( 'scan_on_save', __( 'Scan on save', 'codo-content-security-policy' ), __( 'Check published content against the policy in the background after it is saved.', 'codo-content-security-policy' ) );
		$this->checkbox_row( 'purge_caches', __( 'Purge page caches', 'codo-content-security-policy' ), __( 'Clear page caches (WP Super Cache, W3 Total Cache, WP Rocket, LiteSpeed, Nginx Helper, SiteGround, WP-Optimize, Breeze) when the policy changes, so visitors get the new headers. Other caches and CDNs can use the codo_csp_purge_caches action.', 'codo-content-security-policy' ) );

		$reporting = (string) $this->settings->get( 'reporting' );
		$locked    = $this->settings->is_locked( 'reporting' );
		echo '<tr><th scope="row">' . esc_html__( 'Violation reports', 'codo-content-security-policy' ) . '</th><td><fieldset' . ( $locked ? ' disabled' : '' ) . '>';
		$choices = array(
			Settings::REPORTING_BUILTIN  => __( 'Collect them on this site (for a set period, started on the Reports tab)', 'codo-content-security-policy' ),
			Settings::REPORTING_EXTERNAL => __( 'Send them to an external collector', 'codo-content-security-policy' ),
			Settings::REPORTING_OFF      => __( 'Off', 'codo-content-security-policy' ),
		);
		foreach ( $choices as $value => $label ) {
			echo '<label><input type="radio" name="reporting" value="' . esc_attr( $value ) . '"' . checked( $reporting, $value, false ) . '> ' . esc_html( $label ) . '</label><br>';
		}
		echo '<p><label for="codo-csp-external-uri">' . esc_html__( 'External collector URL', 'codo-content-security-policy' ) . '</label><br><input type="url" class="regular-text code" id="codo-csp-external-uri" name="external_uri" value="' . esc_attr( (string) $this->settings->get( 'external_uri' ) ) . '" placeholder="https://"></p>';
		echo '</fieldset>';
		if ( $locked ) {
			echo '<p class="description">' . esc_html__( 'Set by CODO_CSP_REPORT_URI in wp-config.php.', 'codo-content-security-policy' ) . '</p>';
		}
		echo '</td></tr></tbody></table>';
		submit_button();
		echo '</form>';

		echo '<h2>' . esc_html__( 'Configuration in wp-config.php', 'codo-content-security-policy' ) . '</h2>';
		echo '<p>' . esc_html__( 'These constants override the settings above and show as read-only:', 'codo-content-security-policy' ) . '</p>';
		echo '<pre><code>define( \'CODO_CSP_DISABLE\', true );          // ' . esc_html__( 'Send no policy headers at all.', 'codo-content-security-policy' ) . "\n";
		echo 'define( \'CODO_CSP_MODE\', \'enforce\' );        // ' . esc_html__( 'Or report-only.', 'codo-content-security-policy' ) . "\n";
		echo 'define( \'CODO_CSP_REPORT_URI\', \'https://...\' ); // ' . esc_html__( 'External collector.', 'codo-content-security-policy' ) . "\n";
		echo 'define( \'CODO_CSP_LOGIN\', false );           // ' . esc_html__( 'No policy on wp-login.php.', 'codo-content-security-policy' ) . '</code></pre>';
	}

	/**
	 * A checkbox row.
	 *
	 * @param string $key         Setting key.
	 * @param string $label       Label.
	 * @param string $description Description.
	 * @return void
	 */
	private function checkbox_row( $key, $label, $description ) {
		$locked = $this->settings->is_locked( $key );
		$id     = 'codo-csp-' . $key;
		echo '<tr><th scope="row"><label for="' . esc_attr( $id ) . '">' . esc_html( $label ) . '</label></th><td>';
		echo '<input type="checkbox" id="' . esc_attr( $id ) . '" name="' . esc_attr( $key ) . '" value="1"' . checked( (bool) $this->settings->get( $key ), true, false ) . ( $locked ? ' disabled' : '' ) . '> ';
		echo '<span class="description">' . esc_html( $description ) . '</span>';
		if ( $locked ) {
			echo '<p class="description">' . esc_html__( 'Set in wp-config.php.', 'codo-content-security-policy' ) . '</p>';
		}
		echo '</td></tr>';
	}
}
