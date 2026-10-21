<?php
/**
 * Sends the policy headers on front-end and login responses.
 *
 * @package CodoDigital\Csp
 */

namespace CodoDigital\Csp\Http;

use CodoDigital\Csp\Settings\PolicyStore;
use CodoDigital\Csp\Settings\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Builds and emits Content-Security-Policy headers.
 *
 * Front end: on send_headers, which WordPress fires for front-end page
 * requests only (not wp-admin, admin-ajax, REST or cron). Logged-in users
 * get the same policy as visitors, except inside front-end page builders and
 * the Customizer preview, which are editors that inject inline code.
 *
 * Login: on login_init, with its own policy, when enabled.
 */
class HeaderSender {

	const REPORT_GROUP = 'codo-csp';

	/**
	 * Query arguments that put a front-end request into a page builder's
	 * editing mode.
	 */
	const BUILDER_QUERY_ARGS = array(
		'elementor-preview', // Elementor.
		'et_fb',             // Divi Visual Builder.
		'fl_builder',        // Beaver Builder.
		'bricks',            // Bricks (bricks=run).
		'ct_builder',        // Oxygen.
		'vc_editable',       // WPBakery front-end editor.
		'tve',               // Thrive Architect.
		'brizy-edit-iframe', // Brizy.
		'fb-edit',           // Fusion Builder (Avada).
	);

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
	 * Emits one header line; defaults to header().
	 *
	 * @var callable
	 */
	private $emit;

	/**
	 * Returns whether headers were already sent; defaults to headers_sent().
	 *
	 * @var callable
	 */
	private $headers_sent;

	/**
	 * Constructor.
	 *
	 * @param Settings      $settings     Settings.
	 * @param PolicyStore   $store        Policies.
	 * @param callable|null $emit         Header emitter (tests).
	 * @param callable|null $headers_sent headers_sent replacement (tests).
	 */
	public function __construct( Settings $settings, PolicyStore $store, $emit = null, $headers_sent = null ) {
		$this->settings     = $settings;
		$this->store        = $store;
		$this->emit         = null !== $emit ? $emit : array( __CLASS__, 'php_header' );
		$this->headers_sent = null !== $headers_sent ? $headers_sent : 'headers_sent';
	}

	/**
	 * Default emitter.
	 *
	 * @codeCoverageIgnore
	 * @param string $line Header line.
	 * @return void
	 */
	public static function php_header( $line ) {
		header( $line, false );
	}

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function register() {
		add_action( 'send_headers', array( $this, 'send_front' ) );
		add_action( 'login_init', array( $this, 'send_login' ) );
	}

	/**
	 * Front-end responses.
	 *
	 * @return void
	 */
	public function send_front() {
		if ( $this->should_skip_front() ) {
			return;
		}
		$this->emit_all( $this->build( 'site' ) );
	}

	/**
	 * Responses from wp-login.php.
	 *
	 * @return void
	 */
	public function send_login() {
		if ( ! $this->settings->get( 'login_enabled' ) ) {
			return;
		}
		$this->emit_all( $this->build( 'login' ) );
	}

	/**
	 * Whether this front-end request should not get a policy.
	 *
	 * @return bool
	 */
	public function should_skip_front() {
		$skip = false;

		if ( $this->settings->get( 'skip_builders' ) && $this->is_builder_request() ) {
			$skip = true;
		}

		/**
		 * Filters whether to skip the policy for this front-end request.
		 *
		 * @param bool $skip Whether to skip.
		 */
		return (bool) apply_filters( 'codo_csp_skip_request', $skip );
	}

	/**
	 * Whether the request is the Customizer preview or a page builder's
	 * editing view, for a user who can edit.
	 *
	 * @return bool
	 */
	public function is_builder_request() {
		if ( function_exists( 'is_customize_preview' ) && is_customize_preview() ) {
			return true;
		}
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only check of which view is requested.
		$requested = false;
		foreach ( self::BUILDER_QUERY_ARGS as $arg ) {
			if ( isset( $_GET[ $arg ] ) ) {
				$requested = true;
				break;
			}
		}
		// phpcs:enable
		return $requested && current_user_can( 'edit_posts' );
	}

	/**
	 * Whether this is a request for a post embed (the iframe other sites
	 * show for a pasted link). send_headers runs before the main query, so
	 * this looks at the URL rather than is_embed().
	 *
	 * @return bool
	 */
	public function is_embed_request() {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only check of which view is requested.
		if ( isset( $_GET['embed'] ) ) {
			return true;
		}
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		// phpcs:enable
		$path = (string) wp_parse_url( $uri, PHP_URL_PATH );
		return 1 === preg_match( '~/embed/?$~', $path );
	}

	/**
	 * The headers for a context, as name => list of values.
	 *
	 * @param string   $context site or login.
	 * @param int|null $now     Timestamp.
	 * @return array<string, string[]>
	 */
	public function build( $context, $now = null ) {
		if ( $this->settings->is_disabled() ) {
			return array();
		}

		$live  = $this->store->live( $context );
		$draft = $this->settings->is_enforcing() ? $this->store->draft( $context ) : null;
		if ( 'site' === $context && $this->is_embed_request() ) {
			// Post embeds (/embed/) exist to be framed by other sites.
			$live  = $live->without_directive( 'frame-ancestors' );
			$draft = null === $draft ? null : $draft->without_directive( 'frame-ancestors' );
		}
		$uri    = $this->settings->report_uri( $now, $context );
		$extra  = '' !== $uri ? array( 'report-uri ' . $uri, 'report-to ' . self::REPORT_GROUP ) : array();
		$header = array();

		if ( $this->settings->is_enforcing() ) {
			$header['Content-Security-Policy'] = array( $live->compile( (bool) $this->settings->get( 'upgrade_insecure' ), $extra ) );
			if ( null !== $draft ) {
				$header['Content-Security-Policy-Report-Only'] = array( $draft->compile( false, $extra ) );
			}
		} else {
			// upgrade-insecure-requests is ignored in Report-Only (and logs a console warning).
			$header['Content-Security-Policy-Report-Only'] = array( $live->compile( false, $extra ) );
		}

		if ( '' !== $uri ) {
			$header['Reporting-Endpoints'] = array( self::REPORT_GROUP . '="' . $uri . '"' );
		}

		/**
		 * Filters the policy headers before they are sent.
		 *
		 * @param array<string, string[]> $header  Header name => values.
		 * @param string                  $context site or login.
		 */
		$filtered = apply_filters( 'codo_csp_headers', $header, $context );
		return is_array( $filtered ) ? $filtered : $header;
	}

	/**
	 * Emit headers, unless output has started.
	 *
	 * @param array<string, string[]> $headers Headers.
	 * @return void
	 */
	private function emit_all( array $headers ) {
		if ( empty( $headers ) || call_user_func( $this->headers_sent ) ) {
			return;
		}
		foreach ( $headers as $name => $values ) {
			foreach ( (array) $values as $value ) {
				$value = str_replace( array( "\r", "\n" ), '', (string) $value );
				if ( '' !== $value ) {
					call_user_func( $this->emit, $name . ': ' . $value );
				}
			}
		}
	}
}
