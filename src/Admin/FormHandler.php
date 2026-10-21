<?php
/**
 * Handles the admin screens' form posts.
 *
 * @package CodoDigital\Csp
 */

namespace CodoDigital\Csp\Admin;

use CodoDigital\Csp\Policy\Directives;
use CodoDigital\Csp\Policy\InvalidSourceException;
use CodoDigital\Csp\Policy\Presets;
use CodoDigital\Csp\Reports\ReportRepository;
use CodoDigital\Csp\Scan\ScanScheduler;
use CodoDigital\Csp\Settings\PolicyStore;
use CodoDigital\Csp\Settings\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Every handler checks a capability and a nonce, then redirects back with a
 * notice. There are no AJAX or REST endpoints.
 */
class FormHandler {

	const ACTIONS = array( 'add_rule', 'remove_rule', 'preset', 'draft', 'mode', 'settings', 'reporting', 'clear_reports', 'allow_report', 'scan' );

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
	 * Ends the request after a redirect.
	 *
	 * @var callable
	 */
	private $terminate;

	/**
	 * Constructor.
	 *
	 * @param Settings         $settings  Settings.
	 * @param PolicyStore      $store     Policies.
	 * @param ReportRepository $reports   Reports.
	 * @param ScanScheduler    $scheduler Scans.
	 * @param Notices          $notices   Notices.
	 * @param callable|null    $terminate Called after redirecting; defaults to exit.
	 */
	public function __construct( Settings $settings, PolicyStore $store, ReportRepository $reports, ScanScheduler $scheduler, Notices $notices, $terminate = null ) {
		$this->settings  = $settings;
		$this->store     = $store;
		$this->reports   = $reports;
		$this->scheduler = $scheduler;
		$this->notices   = $notices;
		$this->terminate = null !== $terminate ? $terminate : array( __CLASS__, 'exit_request' );
	}

	/**
	 * Default terminator.
	 *
	 * @codeCoverageIgnore
	 * @return void
	 */
	public static function exit_request() {
		exit;
	}

	/**
	 * Register admin-post handlers.
	 *
	 * @return void
	 */
	public function register() {
		foreach ( self::ACTIONS as $action ) {
			add_action( 'admin_post_codo_csp_' . $action, array( $this, 'handle_' . $action ) );
		}
	}

	/**
	 * Nonce action for a form.
	 *
	 * @param string $action Action without prefix.
	 * @return string
	 */
	public static function nonce_action( $action ) {
		return 'codo_csp_' . $action;
	}

	/**
	 * A posted text field.
	 *
	 * @param string $key Key.
	 * @return string
	 */
	private function field( $key ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in guard() before any field is read.
		return isset( $_POST[ $key ] ) && is_string( $_POST[ $key ] ) ? trim( sanitize_text_field( wp_unslash( $_POST[ $key ] ) ) ) : '';
	}

	/**
	 * A posted source: like a text field, but without sanitize_text_field
	 * stripping characters a source may contain (quotes are kept; Source
	 * validates strictly).
	 *
	 * @param string $key Key.
	 * @return string
	 */
	private function source_field( $key ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Verified in guard(); validated by Source::normalise.
		return isset( $_POST[ $key ] ) && is_string( $_POST[ $key ] ) ? trim( wp_unslash( $_POST[ $key ] ) ) : '';
	}

	/**
	 * The scope (site or network) and context of a posted form.
	 *
	 * @return array{0: string, 1: string}
	 */
	private function scope_and_context() {
		$scope   = 'network' === $this->field( 'scope' ) ? 'network' : 'site';
		$context = $this->field( 'context' );
		return array( $scope, PolicyStore::is_context( $context ) ? $context : 'site' );
	}

	/**
	 * Check the nonce and capability.
	 *
	 * @param string $action Action without prefix.
	 * @param string $scope  site or network.
	 * @return void
	 */
	private function guard( $action, $scope = 'site' ) {
		$capability = 'network' === $scope ? Capability::network() : Capability::site();
		if ( ! current_user_can( $capability ) ) {
			wp_die( esc_html__( 'You do not have permission to change the content security policy.', 'codo-content-security-policy' ), 403 );
		}
		check_admin_referer( self::nonce_action( $action ) );
	}

	/**
	 * Redirect back to a tab and end the request.
	 *
	 * @param string               $scope site or network.
	 * @param string               $tab   Tab.
	 * @param array<string, mixed> $args  Extra query args.
	 * @return void
	 */
	private function back( $scope, $tab, array $args = array() ) {
		$url = 'network' === $scope
			? network_admin_url( 'settings.php?page=' . NetworkPage::SLUG )
			: admin_url( 'options-general.php?page=' . AdminPage::SLUG );
		wp_safe_redirect( add_query_arg( array_merge( array( 'tab' => $tab ), $args ), $url ) );
		call_user_func( $this->terminate );
	}

	/**
	 * Tab that shows a context's policy.
	 *
	 * @param string $context Context.
	 * @return string
	 */
	private static function policy_tab( $context ) {
		return 'login' === $context ? 'login' : 'policy';
	}

	/**
	 * Explain where an added rule went.
	 *
	 * @param array{source: string, target: string, inherited: string[]} $result    Result of PolicyStore::add.
	 * @param string                                                     $directive Directive.
	 * @return void
	 */
	private function report_add( array $result, $directive ) {
		if ( 'exists' === $result['target'] ) {
			$this->notices->add(
				'info',
				/* translators: 1: source, 2: directive. */
				sprintf( __( '%1$s is already allowed in %2$s.', 'codo-content-security-policy' ), $result['source'], $directive )
			);
			return;
		}
		if ( 'draft' === $result['target'] ) {
			$this->notices->add(
				'warning',
				sprintf(
					/* translators: 1: source, 2: directive. */
					__( '%1$s was added to %2$s in the draft, because it would tighten the enforced policy. The draft is tested in Report-Only alongside the live policy; promote it once its reports are clean.', 'codo-content-security-policy' ),
					$result['source'],
					$directive
				)
			);
		} else {
			$this->notices->add(
				'success',
				/* translators: 1: source, 2: directive. */
				sprintf( __( 'Allowed %1$s in %2$s.', 'codo-content-security-policy' ), $result['source'], $directive )
			);
		}
		if ( ! empty( $result['inherited'] ) ) {
			$this->notices->add(
				'info',
				sprintf(
					/* translators: 1: directive, 2: list of sources. */
					__( '%1$s was new, so the sources it used to inherit through fallback were copied in (%2$s), keeping everything that loads today allowed.', 'codo-content-security-policy' ),
					$directive,
					implode( ' ', $result['inherited'] )
				)
			);
		}
	}

	/**
	 * Add a source.
	 *
	 * @return void
	 */
	public function handle_add_rule() {
		list( $scope, $context ) = $this->scope_and_context();
		$this->guard( 'add_rule', $scope );

		$directive = $this->field( 'directive' );
		$source    = $this->source_field( 'source' );
		$note      = $this->field( 'note' );
		$origin    = in_array( $this->field( 'origin' ), array( 'scan', 'report' ), true ) ? $this->field( 'origin' ) : 'manual';
		$tab       = in_array( $this->field( 'return' ), array( 'scan', 'reports' ), true ) ? $this->field( 'return' ) : self::policy_tab( $context );

		try {
			if ( 'network' === $scope ) {
				$normalised = $this->store->network_add( $context, $directive, $source, $note );
				/* translators: 1: source, 2: directive. */
				$this->notices->add( 'success', sprintf( __( 'Added %1$s to %2$s for every site.', 'codo-content-security-policy' ), $normalised, $directive ) );
			} else {
				$this->report_add( $this->store->add( $context, $directive, $source, $origin, $note ), $directive );
			}
		} catch ( InvalidSourceException $e ) {
			$this->notices->add( 'error', $e->getMessage() );
		}
		$this->back( $scope, 'network' === $scope ? $context : $tab );
	}

	/**
	 * Remove a source.
	 *
	 * @return void
	 */
	public function handle_remove_rule() {
		list( $scope, $context ) = $this->scope_and_context();
		$this->guard( 'remove_rule', $scope );

		$directive = $this->field( 'directive' );
		$source    = $this->source_field( 'source' );

		if ( 'network' === $scope ) {
			if ( $this->store->network_remove( $context, $directive, $source ) ) {
				/* translators: 1: source, 2: directive. */
				$this->notices->add( 'success', sprintf( __( 'Removed %1$s from %2$s on every site.', 'codo-content-security-policy' ), $source, $directive ) );
			}
			$this->back( $scope, $context );
			return;
		}

		try {
			$target = $this->store->remove( $context, $directive, $source );
			if ( 'draft' === $target ) {
				$this->notices->add(
					'warning',
					/* translators: 1: source, 2: directive. */
					sprintf( __( 'Removing %1$s from %2$s tightens the enforced policy, so the removal is in the draft. Promote the draft once its reports are clean.', 'codo-content-security-policy' ), $source, $directive )
				);
			} elseif ( 'live' === $target ) {
				/* translators: 1: source, 2: directive. */
				$this->notices->add( 'success', sprintf( __( 'Removed %1$s from %2$s.', 'codo-content-security-policy' ), $source, $directive ) );
			}
		} catch ( InvalidSourceException $e ) {
			$this->notices->add( 'error', $e->getMessage() );
		}
		$this->back( $scope, self::policy_tab( $context ) );
	}

	/**
	 * Add a preset.
	 *
	 * @return void
	 */
	public function handle_preset() {
		list( $scope, $context ) = $this->scope_and_context();
		$this->guard( 'preset', $scope );

		$id      = $this->field( 'preset' );
		$presets = Presets::all();
		if ( ! isset( $presets[ $id ] ) ) {
			$this->notices->add( 'error', __( 'Unknown preset.', 'codo-content-security-policy' ) );
			$this->back( $scope, 'network' === $scope ? $context : self::policy_tab( $context ) );
			return;
		}

		if ( 'network' === $scope ) {
			$added = 0;
			foreach ( $presets[ $id ]['rules'] as $directive => $sources ) {
				foreach ( (array) $sources as $source ) {
					try {
						$this->store->network_add( $context, (string) $directive, (string) $source );
						++$added;
					} catch ( InvalidSourceException $e ) {
						continue;
					}
				}
			}
		} else {
			$added = $this->store->apply_preset( $context, $id );
		}

		$this->notices->add(
			'success',
			sprintf(
				/* translators: 1: preset name, 2: number of sources. */
				_n( '%1$s: %2$d source added.', '%1$s: %2$d sources added.', $added, 'codo-content-security-policy' ),
				$presets[ $id ]['label'],
				$added
			)
		);
		$this->back( $scope, 'network' === $scope ? $context : self::policy_tab( $context ) );
	}

	/**
	 * Promote or discard a draft.
	 *
	 * @return void
	 */
	public function handle_draft() {
		list( , $context ) = $this->scope_and_context();
		$this->guard( 'draft' );

		if ( 'promote' === $this->field( 'op' ) ) {
			if ( $this->store->promote( $context ) ) {
				$this->notices->add( 'success', __( 'The draft is now the live policy.', 'codo-content-security-policy' ) );
			}
		} elseif ( $this->store->discard( $context ) ) {
			$this->notices->add( 'success', __( 'The draft was discarded.', 'codo-content-security-policy' ) );
		}
		$this->back( 'site', self::policy_tab( $context ) );
	}

	/**
	 * Switch between Report-Only and enforcing.
	 *
	 * @return void
	 */
	public function handle_mode() {
		$this->guard( 'mode' );
		$tab = sanitize_key( $this->field( 'return' ) );
		$tab = '' !== $tab ? $tab : 'policy';

		if ( $this->settings->is_locked( 'mode' ) ) {
			$this->notices->add( 'error', __( 'The mode is set by CODO_CSP_MODE in wp-config.php.', 'codo-content-security-policy' ) );
			$this->back( 'site', $tab );
			return;
		}

		$enforce = Settings::MODE_ENFORCE === $this->field( 'mode' );
		if ( $enforce ) {
			$this->settings->update( array( 'mode' => Settings::MODE_ENFORCE ) );
			$this->notices->add( 'success', __( 'The policy is now enforced: browsers block anything it does not allow. Changes that only add sources apply straight away; removals go into a draft that is tested first.', 'codo-content-security-policy' ) );
		} else {
			$promoted = $this->store->promote_all();
			$this->settings->update( array( 'mode' => Settings::MODE_REPORT_ONLY ) );
			$this->notices->add( 'success', __( 'The policy is now Report-Only: nothing is blocked, violations are only reported.', 'codo-content-security-policy' ) );
			if ( $promoted > 0 ) {
				$this->notices->add( 'info', __( 'Drafts were made live, since nothing is enforced in Report-Only.', 'codo-content-security-policy' ) );
			}
		}

		/**
		 * Fires after switching between Report-Only and enforcing.
		 *
		 * @param bool $enforce Whether the policy is now enforced.
		 */
		do_action( 'codo_csp_mode_changed', $enforce );
		$this->back( 'site', $tab );
	}

	/**
	 * Save the settings tab.
	 *
	 * @return void
	 */
	public function handle_settings() {
		$this->guard( 'settings' );

		$changes = array();
		foreach ( array( 'login_enabled', 'skip_builders', 'upgrade_insecure', 'purge_caches', 'scan_on_save' ) as $key ) {
			// A value fixed in wp-config.php keeps its stored value for when the constant goes.
			if ( ! $this->settings->is_locked( $key ) ) {
				$changes[ $key ] = '1' === $this->field( $key );
			}
		}

		$reporting = $this->field( 'reporting' );
		$uri       = $this->field( 'external_uri' );
		if ( Settings::REPORTING_EXTERNAL === $reporting ) {
			$clean = Settings::sanitize_uri( $uri );
			if ( '' === $clean ) {
				$this->notices->add( 'error', __( 'Enter an https:// URL for the external report collector.', 'codo-content-security-policy' ) );
				$this->back( 'site', 'settings' );
				return;
			}
			$changes['external_uri'] = $clean;
		}
		if ( in_array( $reporting, array( Settings::REPORTING_BUILTIN, Settings::REPORTING_EXTERNAL, Settings::REPORTING_OFF ), true ) ) {
			$changes['reporting'] = $reporting;
		}

		$this->settings->update( $changes );

		/** This action is documented in src/Settings/PolicyStore.php */
		do_action( 'codo_csp_policy_changed', 'site', 'settings' );
		$this->notices->add( 'success', __( 'Settings saved.', 'codo-content-security-policy' ) );
		$this->back( 'site', 'settings' );
	}

	/**
	 * Start or stop built-in report collection.
	 *
	 * @return void
	 */
	public function handle_reporting() {
		$this->guard( 'reporting' );

		if ( 'stop' === $this->field( 'op' ) ) {
			$this->settings->stop_collecting();
			$this->notices->add( 'success', __( 'Report collection stopped. Browsers that still have a cached page may keep sending reports for a while; they are ignored.', 'codo-content-security-policy' ) );
		} else {
			$days = absint( $this->field( 'days' ) );
			$this->settings->collect_for( $days );
			$this->notices->add(
				'success',
				sprintf(
					/* translators: %s: date and time. */
					__( 'Collecting reports until %s.', 'codo-content-security-policy' ),
					wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $this->settings->get( 'report_until' ) )
				)
			);
		}

		/** This action is documented in src/Settings/PolicyStore.php */
		do_action( 'codo_csp_policy_changed', 'site', 'settings' );
		$this->back( 'site', 'reports' );
	}

	/**
	 * Delete all reports.
	 *
	 * @return void
	 */
	public function handle_clear_reports() {
		$this->guard( 'clear_reports' );
		$this->reports->clear();
		$this->notices->add( 'success', __( 'Reports cleared.', 'codo-content-security-policy' ) );
		$this->back( 'site', 'reports' );
	}

	/**
	 * Allow what a report says was blocked.
	 *
	 * @return void
	 */
	public function handle_allow_report() {
		$this->guard( 'allow_report' );

		$row = $this->reports->find( absint( $this->field( 'id' ) ) );
		if ( null === $row ) {
			$this->notices->add( 'error', __( 'That report no longer exists.', 'codo-content-security-policy' ) );
			$this->back( 'site', 'reports' );
			return;
		}

		$suggestion = self::suggest_from_report( $row, $this->store );
		if ( null === $suggestion ) {
			$this->notices->add( 'error', __( 'There is no source to add for this report.', 'codo-content-security-policy' ) );
			$this->back( 'site', 'reports' );
			return;
		}

		try {
			$this->report_add( $this->store->add( $suggestion['context'], $suggestion['directive'], $suggestion['source'], 'report' ), $suggestion['directive'] );
		} catch ( InvalidSourceException $e ) {
			$this->notices->add( 'error', $e->getMessage() );
		}
		$this->back( 'site', 'reports' );
	}

	/**
	 * What to add to allow a reported violation.
	 *
	 * @param array<string, mixed> $row   Report row.
	 * @param PolicyStore          $store Policies.
	 * @return array{context: string, directive: string, source: string}|null
	 */
	public static function suggest_from_report( array $row, PolicyStore $store ) {
		$context   = isset( $row['context'] ) && 'login' === $row['context'] ? 'login' : 'site';
		$directive = (string) $row['directive'];
		if ( ! Directives::is_known( $directive ) ) {
			return null;
		}
		$keywords = array(
			'inline'    => "'unsafe-inline'",
			'eval'      => "'unsafe-eval'",
			'wasm-eval' => "'wasm-unsafe-eval'",
		);
		$blocked  = (string) $row['blocked'];
		if ( isset( $keywords[ $blocked ] ) ) {
			$source = $keywords[ $blocked ];
		} elseif ( preg_match( '~^[a-z][a-z0-9+.\-]*:(//.+)?$~', $blocked ) ) {
			$source = $blocked;
		} else {
			return null;
		}
		return array(
			'context'   => $context,
			'directive' => Directives::target( $store->live( $context ), $directive ),
			'source'    => $source,
		);
	}

	/**
	 * Run or queue scans.
	 *
	 * @return void
	 */
	public function handle_scan() {
		$this->guard( 'scan' );
		$op = $this->field( 'op' );

		if ( 'recent' === $op ) {
			$queued = $this->scheduler->queue_recent();
			$this->notices->add(
				'success',
				sprintf(
					/* translators: %d: number of pages. */
					_n( '%d page queued for scanning in the background. Results appear below as they finish.', '%d pages queued for scanning in the background. Results appear below as they finish.', $queued, 'codo-content-security-policy' ),
					$queued
				)
			);
			$this->back( 'site', 'scan' );
			return;
		}

		if ( 'forget' === $op ) {
			$this->scheduler->forget( esc_url_raw( $this->field( 'url' ) ) );
			$this->back( 'site', 'scan' );
			return;
		}

		$url = 'login' === $op ? wp_login_url() : esc_url_raw( $this->field( 'url' ) );
		if ( '' === $url ) {
			$url = home_url( '/' );
		}
		// The login page may live at a custom URL (WPS Hide Login and the like).
		$result = $this->scheduler->scan_url( $url, 'login' === $op ? 'login' : null );

		if ( 'error' === $result['status'] ) {
			$this->notices->add( 'error', $result['error'] );
		} elseif ( 'issues' === $result['status'] ) {
			$this->notices->add( 'warning', __( 'The scan found resources the policy does not allow. See below.', 'codo-content-security-policy' ) );
		} else {
			/* translators: %d: number of resources. */
			$this->notices->add( 'success', sprintf( __( 'All %d resources found are allowed.', 'codo-content-security-policy' ), (int) $result['checked'] ) );
		}
		$this->back( 'site', 'scan' );
	}
}
