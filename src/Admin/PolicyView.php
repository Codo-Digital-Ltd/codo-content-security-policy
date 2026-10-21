<?php
/**
 * Renders a context's rules with add, remove and preset forms.
 *
 * @package CodoDigital\Csp
 */

namespace CodoDigital\Csp\Admin;

use CodoDigital\Csp\Policy\Directives;
use CodoDigital\Csp\Policy\Policy;
use CodoDigital\Csp\Policy\Presets;
use CodoDigital\Csp\Policy\Source;
use CodoDigital\Csp\Settings\PolicyStore;

defined( 'ABSPATH' ) || exit;

/**
 * Shared by the site screen and the network defaults screen. Server-rendered
 * forms only, no JavaScript.
 */
class PolicyView {

	/**
	 * Policies.
	 *
	 * @var PolicyStore
	 */
	private $store;

	/**
	 * Constructor.
	 *
	 * @param PolicyStore $store Policies.
	 */
	public function __construct( PolicyStore $store ) {
		$this->store = $store;
	}

	/**
	 * Hidden fields every form posts.
	 *
	 * @param string               $action  Action without prefix.
	 * @param string               $context Context.
	 * @param string               $scope   site or network.
	 * @param array<string, mixed> $extra   More hidden fields.
	 * @return void
	 */
	public static function hidden( $action, $context, $scope, array $extra = array() ) {
		echo '<input type="hidden" name="action" value="' . esc_attr( 'codo_csp_' . $action ) . '">';
		echo '<input type="hidden" name="context" value="' . esc_attr( $context ) . '">';
		echo '<input type="hidden" name="scope" value="' . esc_attr( $scope ) . '">';
		foreach ( $extra as $name => $value ) {
			echo '<input type="hidden" name="' . esc_attr( $name ) . '" value="' . esc_attr( (string) $value ) . '">';
		}
		wp_nonce_field( FormHandler::nonce_action( $action ) );
	}

	/**
	 * Form opening tag posting to admin-post.php.
	 *
	 * @param string $css_class CSS class.
	 * @return void
	 */
	public static function open_form( $css_class = '' ) {
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"' . ( '' !== $css_class ? ' class="' . esc_attr( $css_class ) . '"' : '' ) . '>';
	}

	/**
	 * A small inline form with one button.
	 *
	 * @param string               $action  Action.
	 * @param string               $context Context.
	 * @param string               $scope   Scope.
	 * @param array<string, mixed> $fields  Hidden fields.
	 * @param string               $label   Button label.
	 * @param string               $css_class   Button classes.
	 * @return void
	 */
	public static function button( $action, $context, $scope, array $fields, $label, $css_class = 'button button-small' ) {
		self::open_form( 'codo-csp-inline' );
		self::hidden( $action, $context, $scope, $fields );
		echo '<button type="submit" class="' . esc_attr( $css_class ) . '">' . esc_html( $label ) . '</button></form>';
	}

	/**
	 * Render the policy of a context.
	 *
	 * @param string $context site or login.
	 * @param string $scope   site or network.
	 * @return void
	 */
	public function render( $context, $scope ) {
		$network = $this->store->network( $context );

		if ( 'network' === $scope ) {
			$working = $network;
			$live    = $network;
			$network = new Policy();
		} else {
			$live    = $this->store->local( $context );
			$draft   = $this->store->local_draft( $context );
			$working = null === $draft ? $live : $draft;
			if ( null !== $draft ) {
				$this->render_draft_banner( $context, $live, $draft );
			}
		}

		// Sources copied in when a network default created a directive.
		$extra = 'network' === $scope ? new Policy() : PolicyStore::compose( $network, $working );
		$this->render_table( $context, $scope, $network, $live, $working, $extra );
		$this->render_add_form( $context, $scope );
		$this->render_presets( $context, $scope );
	}

	/**
	 * The draft summary with promote and discard.
	 *
	 * @param string $context Context.
	 * @param Policy $live    Live local rules.
	 * @param Policy $draft   Draft local rules.
	 * @return void
	 */
	private function render_draft_banner( $context, Policy $live, Policy $draft ) {
		$added   = $draft->diff( $live );
		$removed = $live->diff( $draft );

		echo '<div class="notice notice-warning inline codo-csp-draft"><p><strong>' . esc_html__( 'A draft is being tested.', 'codo-content-security-policy' ) . '</strong> ';
		echo esc_html(
			sprintf(
				/* translators: %s: date. */
				__( 'Since %s, visitors\' browsers have checked the draft in Report-Only alongside the enforced policy. Nothing in the draft is blocked yet. Check the Reports tab for anything only the draft would block, then promote it.', 'codo-content-security-policy' ),
				wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $this->store->draft_started( $context ) )
			)
		);
		echo '</p><ul class="codo-csp-changes">';
		foreach ( $added as $rule ) {
			echo '<li><span class="codo-csp-add">+</span> <code>' . esc_html( $rule['d'] . ' ' . $rule['s'] ) . '</code></li>';
		}
		foreach ( $removed as $rule ) {
			echo '<li><span class="codo-csp-remove">&minus;</span> <code>' . esc_html( $rule['d'] . ' ' . $rule['s'] ) . '</code></li>';
		}
		echo '</ul><p>';
		self::button( 'draft', $context, 'site', array( 'op' => 'promote' ), __( 'Promote draft to live', 'codo-content-security-policy' ), 'button button-primary' );
		echo ' ';
		self::button( 'draft', $context, 'site', array( 'op' => 'discard' ), __( 'Discard draft', 'codo-content-security-policy' ), 'button' );
		echo '</p></div>';
	}

	/**
	 * The rules table.
	 *
	 * @param string $context Context.
	 * @param string $scope   Scope.
	 * @param Policy $network Network rules (read-only here).
	 * @param Policy $live    Live local rules.
	 * @param Policy $working Draft (or live) local rules.
	 * @param Policy $merged  Network and local rules as merged (for inherited sources).
	 * @return void
	 */
	private function render_table( $context, $scope, Policy $network, Policy $live, Policy $working, Policy $merged ) {
		echo '<table class="widefat striped codo-csp-rules"><thead><tr>';
		echo '<th scope="col">' . esc_html__( 'Directive', 'codo-content-security-policy' ) . '</th>';
		echo '<th scope="col">' . esc_html__( 'Source', 'codo-content-security-policy' ) . '</th>';
		echo '<th scope="col">' . esc_html__( 'Added by', 'codo-content-security-policy' ) . '</th>';
		echo '<th scope="col">' . esc_html__( 'Note', 'codo-content-security-policy' ) . '</th>';
		echo '<th scope="col"><span class="screen-reader-text">' . esc_html__( 'Actions', 'codo-content-security-policy' ) . '</span></th>';
		echo '</tr></thead><tbody>';

		$any = false;
		foreach ( Directives::all() as $directive ) {
			$rows = array();
			foreach ( $network->rules() as $rule ) {
				if ( $rule['d'] === $directive ) {
					$rows[] = array( $rule, 'network' );
				}
			}
			foreach ( $merged->rules() as $rule ) {
				if ( $rule['d'] === $directive && 'inherited' === $rule['o'] && ! $network->has( $rule['d'], $rule['s'] ) && ! $working->has( $rule['d'], $rule['s'] ) ) {
					$rows[] = array( $rule, 'network-inherited' );
				}
			}
			foreach ( $working->rules() as $rule ) {
				if ( $rule['d'] === $directive && ! $network->has( $rule['d'], $rule['s'] ) ) {
					$rows[] = array( $rule, $live->has( $rule['d'], $rule['s'] ) ? 'live' : 'pending-add' );
				}
			}
			foreach ( $live->rules() as $rule ) {
				if ( $rule['d'] === $directive && ! $working->has( $rule['d'], $rule['s'] ) ) {
					$rows[] = array( $rule, 'pending-remove' );
				}
			}
			if ( empty( $rows ) ) {
				continue;
			}
			$any   = true;
			$first = true;
			foreach ( $rows as $row ) {
				$this->render_row( $context, $scope, $row[0], $row[1], $first ? count( $rows ) : 0 );
				$first = false;
			}
		}
		if ( ! $any ) {
			echo '<tr><td colspan="5">' . esc_html__( 'No rules yet.', 'codo-content-security-policy' ) . '</td></tr>';
		}
		echo '</tbody></table>';
	}

	/**
	 * One rule row.
	 *
	 * @param string               $context Context.
	 * @param string               $scope   Scope.
	 * @param array<string, mixed> $rule    Rule.
	 * @param string               $state   live, network, pending-add or pending-remove.
	 * @param int                  $rowspan Rows in this directive (0 when not the first).
	 * @return void
	 */
	private function render_row( $context, $scope, array $rule, $state, $rowspan ) {
		echo '<tr class="' . esc_attr( 'codo-csp-' . $state ) . '">';
		if ( $rowspan > 0 ) {
			echo '<th scope="rowgroup" rowspan="' . esc_attr( (string) $rowspan ) . '"><code>' . esc_html( $rule['d'] ) . '</code><p class="description">' . esc_html( Directives::describe( $rule['d'] ) ) . '</p></th>';
		}

		echo '<td><code>' . esc_html( $rule['s'] ) . '</code>';
		if ( 'pending-add' === $state ) {
			echo ' <span class="codo-csp-badge">' . esc_html__( 'in draft', 'codo-content-security-policy' ) . '</span>';
		} elseif ( 'pending-remove' === $state ) {
			echo ' <span class="codo-csp-badge">' . esc_html__( 'removal in draft', 'codo-content-security-policy' ) . '</span>';
		}
		$warning = Source::warning( $rule['d'], $rule['s'] );
		if ( '' !== $warning ) {
			echo '<p class="description">' . esc_html( $warning ) . '</p>';
		}
		echo '</td>';

		echo '<td>' . esc_html( self::origin_label( 'network' === $state ? 'network' : $rule['o'] ) );
		if ( $rule['t'] > 0 ) {
			echo '<br><span class="description">' . esc_html( wp_date( get_option( 'date_format' ), $rule['t'] ) ) . '</span>';
		}
		echo '</td><td>' . esc_html( $rule['n'] ) . '</td><td>';

		$fields = array(
			'directive' => $rule['d'],
			'source'    => $rule['s'],
		);
		if ( 'network' === $state ) {
			echo '<span class="description">' . esc_html__( 'Network default', 'codo-content-security-policy' ) . '</span>';
		} elseif ( 'network-inherited' === $state ) {
			echo '<span class="description">' . esc_html__( 'Kept because a network default created this directive', 'codo-content-security-policy' ) . '</span>';
		} elseif ( 'pending-remove' === $state ) {
			self::button( 'add_rule', $context, $scope, $fields, __( 'Keep', 'codo-content-security-policy' ) );
		} else {
			self::button( 'remove_rule', $context, $scope, $fields, __( 'Remove', 'codo-content-security-policy' ) );
		}
		echo '</td></tr>';
	}

	/**
	 * Human label for a rule's origin.
	 *
	 * @param string $origin Origin.
	 * @return string
	 */
	public static function origin_label( $origin ) {
		if ( 0 === strpos( $origin, 'preset:' ) ) {
			$presets = Presets::all();
			$id      = substr( $origin, 7 );
			/* translators: %s: preset name. */
			return sprintf( __( 'Preset: %s', 'codo-content-security-policy' ), isset( $presets[ $id ] ) ? $presets[ $id ]['label'] : $id );
		}
		$labels = array(
			'default'   => __( 'Default', 'codo-content-security-policy' ),
			'manual'    => __( 'Added by hand', 'codo-content-security-policy' ),
			'scan'      => __( 'From a scan', 'codo-content-security-policy' ),
			'report'    => __( 'From a report', 'codo-content-security-policy' ),
			'inherited' => __( 'Inherited (fallback)', 'codo-content-security-policy' ),
			'network'   => __( 'Network default', 'codo-content-security-policy' ),
		);
		return isset( $labels[ $origin ] ) ? $labels[ $origin ] : $origin;
	}

	/**
	 * The add form.
	 *
	 * @param string $context Context.
	 * @param string $scope   Scope.
	 * @return void
	 */
	private function render_add_form( $context, $scope ) {
		echo '<h2>' . esc_html__( 'Add a source', 'codo-content-security-policy' ) . '</h2>';
		self::open_form( 'codo-csp-add' );
		self::hidden( 'add_rule', $context, $scope );
		$id = 'codo-csp-' . $scope . '-' . $context;
		echo '<p><label for="' . esc_attr( $id . '-directive' ) . '">' . esc_html__( 'Directive', 'codo-content-security-policy' ) . '</label><br><select name="directive" id="' . esc_attr( $id . '-directive' ) . '">';
		foreach ( Directives::all() as $directive ) {
			echo '<option value="' . esc_attr( $directive ) . '">' . esc_html( $directive ) . '</option>';
		}
		echo '</select></p>';
		echo '<p><label for="' . esc_attr( $id . '-source' ) . '">' . esc_html__( 'Source', 'codo-content-security-policy' ) . '</label><br><input type="text" class="regular-text code" name="source" id="' . esc_attr( $id . '-source' ) . '" required placeholder="https://cdn.example.com" aria-describedby="' . esc_attr( $id . '-help' ) . '"></p>';
		echo '<p class="description" id="' . esc_attr( $id . '-help' ) . '">' . esc_html__( 'A host (https://cdn.example.com, *.example.com), a scheme (data:, https:), a keyword (self, none, unsafe-inline, unsafe-eval) or a hash (sha256-...). Pasted URLs keep their path but lose the query string.', 'codo-content-security-policy' ) . '</p>';
		echo '<p><label for="' . esc_attr( $id . '-note' ) . '">' . esc_html__( 'Note (optional)', 'codo-content-security-policy' ) . '</label><br><input type="text" class="regular-text" name="note" maxlength="200" id="' . esc_attr( $id . '-note' ) . '"></p>';
		submit_button( __( 'Add source', 'codo-content-security-policy' ), 'secondary', 'submit', false );
		echo '</form>';
	}

	/**
	 * The presets form.
	 *
	 * @param string $context Context.
	 * @param string $scope   Scope.
	 * @return void
	 */
	private function render_presets( $context, $scope ) {
		echo '<h2>' . esc_html__( 'Add a common service', 'codo-content-security-policy' ) . '</h2>';
		echo '<p class="description">' . esc_html__( 'Adds every source a service needs across directives. Presets only add sources, so they apply straight away even when the policy is enforced.', 'codo-content-security-policy' ) . '</p>';
		self::open_form( 'codo-csp-presets' );
		self::hidden( 'preset', $context, $scope );
		$id = 'codo-csp-preset-' . $scope . '-' . $context;
		echo '<p><label class="screen-reader-text" for="' . esc_attr( $id ) . '">' . esc_html__( 'Service', 'codo-content-security-policy' ) . '</label><select name="preset" id="' . esc_attr( $id ) . '">';
		foreach ( Presets::all() as $preset_id => $preset ) {
			echo '<option value="' . esc_attr( $preset_id ) . '">' . esc_html( $preset['label'] ) . '</option>';
		}
		echo '</select> ';
		submit_button( __( 'Add service', 'codo-content-security-policy' ), 'secondary', 'submit', false );
		echo '</p></form>';
	}
}
