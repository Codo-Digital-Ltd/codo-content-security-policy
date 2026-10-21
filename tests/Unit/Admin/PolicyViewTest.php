<?php
/**
 * Tests for PolicyView.
 *
 * @package CodoDigital\Csp\Tests
 */

namespace CodoDigital\Csp\Tests\Unit\Admin;

use Brain\Monkey\Functions;
use CodoDigital\Csp\Admin\PolicyView;
use CodoDigital\Csp\Settings\PolicyStore;
use CodoDigital\Csp\Settings\Settings;

class PolicyViewTest extends AdminTestCase {

	protected function setUp(): void {
		parent::setUp();
		$this->boot();
	}

	/**
	 * Replace the stored site policy.
	 *
	 * @param array<int, mixed>      $rules Live rules.
	 * @param array<int, mixed>|null $draft Draft rules.
	 * @param string                 $context Context.
	 * @return void
	 */
	private function policy( array $rules, $draft = null, $context = 'site' ) {
		$this->options[ PolicyStore::OPTION ][ $context ] = array(
			'rules' => $rules,
			'draft' => null === $draft ? null : array(
				'rules' => $draft,
				't'     => 1767225600, // 2026-01-01 00:00 UTC.
			),
		);
	}

	private function render( $context = 'site', $scope = 'site' ) {
		ob_start();
		( new PolicyView( $this->store ) )->render( $context, $scope );
		return ob_get_clean();
	}

	/**
	 * The <tr> of a rule.
	 *
	 * @param string $html   HTML.
	 * @param string $source Escaped source.
	 * @return string
	 */
	private static function row( $html, $source ) {
		$found = preg_match( '~<tr class="([^"]+)">((?:(?!</tr>).)*<code>' . preg_quote( $source, '~' ) . '</code>(?:(?!</tr>).)*)</tr>~s', $html, $m );
		return $found ? $m[1] . '|' . $m[2] : '';
	}

	public function test_hidden_fields() {
		ob_start();
		PolicyView::hidden( 'add_rule', 'login', 'site', array( 'return' => 'x"y' ) );
		$html = ob_get_clean();

		$this->assertSame(
			'<input type="hidden" name="action" value="codo_csp_add_rule">'
			. '<input type="hidden" name="context" value="login">'
			. '<input type="hidden" name="scope" value="site">'
			. '<input type="hidden" name="return" value="x&quot;y">'
			. '<input type="hidden" name="_wpnonce" value="nonce-codo_csp_add_rule">',
			$html
		);
	}

	public function test_open_form_and_button() {
		ob_start();
		PolicyView::open_form();
		PolicyView::button( 'draft', 'site', 'site', array( 'op' => 'promote' ), 'Go <now>' );
		$html = ob_get_clean();

		$this->assertStringStartsWith( '<form method="post" action="https://www.example.com/wp-admin/admin-post.php"><form method="post" action="https://www.example.com/wp-admin/admin-post.php" class="codo-csp-inline">', $html );
		$this->assertStringContainsString( 'name="op" value="promote"', $html );
		$this->assertStringEndsWith( '<button type="submit" class="button button-small">Go &lt;now&gt;</button></form>', $html );
	}

	public function test_rules_table_with_live_rules() {
		$this->policy(
			array(
				self::rule( 'script-src', "'self'", 'default', 1767225600 ),
				self::rule( 'script-src', "'unsafe-eval'", 'manual', 0, 'Needed by <the> slider' ),
				self::rule( 'img-src', 'https:', 'preset:google-fonts' ),
			)
		);

		$html = $this->render();

		$this->assertStringContainsString( '<table class="widefat striped codo-csp-rules">', $html );
		$this->assertStringContainsString( '<th scope="rowgroup" rowspan="2"><code>script-src</code>', $html );
		$this->assertStringContainsString( '<th scope="rowgroup" rowspan="1"><code>img-src</code>', $html );

		$self = self::row( $html, '&#039;self&#039;' );
		$this->assertStringStartsWith( 'codo-csp-live|', $self );
		$this->assertStringContainsString( '<td>Default<br><span class="description">2026-01-01 00:00</span></td>', $self );
		$this->assertStringContainsString( 'name="action" value="codo_csp_remove_rule"', $self );
		$this->assertStringContainsString( '>Remove</button>', $self );

		$eval = self::row( $html, '&#039;unsafe-eval&#039;' );
		$this->assertStringContainsString( 'Lets scripts turn strings into code.', $eval );
		$this->assertStringContainsString( '<td>Added by hand</td><td>Needed by &lt;the&gt; slider</td>', $eval );

		$https = self::row( $html, 'https:' );
		$this->assertStringContainsString( 'Allows any host.', $https );
		$this->assertStringContainsString( 'Preset: Google Fonts', $https );

		$this->assertStringNotContainsString( 'No rules yet.', $html );
		$this->assertStringNotContainsString( 'codo-csp-draft', $html, 'no draft banner' );
	}

	public function test_empty_table() {
		$this->policy( array() );
		$html = $this->render();
		$this->assertStringContainsString( '<tr><td colspan="5">No rules yet.</td></tr>', $html );
	}

	public function test_draft_banner_and_pending_rows() {
		Functions\when( 'is_multisite' )->justReturn( true );
		$this->options[ Settings::OPTION ] = array( 'mode' => Settings::MODE_ENFORCE );
		$this->site_options[ PolicyStore::NETWORK_OPTION ] = array(
			'site' => array( self::rule( 'img-src', 'https://cdn.network.test', 'network', 1767225600 ) ),
		);
		$this->policy(
			array(
				self::rule( 'img-src', "'self'" ),
				self::rule( 'img-src', 'data:' ),
				self::rule( 'img-src', 'https://cdn.network.test' ),
			),
			array(
				self::rule( 'img-src', "'self'" ),
				self::rule( 'img-src', 'https://cdn.network.test' ),
				self::rule( 'script-src', "'sha256-abc='", 'scan' ),
			)
		);

		$html = $this->render();

		$this->assertStringContainsString( '<div class="notice notice-warning inline codo-csp-draft"><p><strong>A draft is being tested.</strong> Since 2026-01-01 00:00,', $html );
		$this->assertStringContainsString( '<li><span class="codo-csp-add">+</span> <code>script-src &#039;sha256-abc=&#039;</code></li>', $html );
		$this->assertStringContainsString( '<li><span class="codo-csp-remove">&minus;</span> <code>img-src data:</code></li>', $html );
		$this->assertStringContainsString( 'name="op" value="promote"><input type="hidden" name="_wpnonce" value="nonce-codo_csp_draft"><button type="submit" class="button button-primary">Promote draft to live</button>', $html );
		$this->assertStringContainsString( 'name="op" value="discard"', $html );

		$network = self::row( $html, 'https://cdn.network.test' );
		$this->assertStringStartsWith( 'codo-csp-network|', $network );
		$this->assertStringContainsString( '<td>Network default<br>', $network );
		$this->assertStringContainsString( '<span class="description">Network default</span>', $network );
		$this->assertStringNotContainsString( '<form', $network, 'network defaults cannot be removed here' );
		$this->assertSame( 1, substr_count( $html, '<code>https://cdn.network.test</code>' ), 'shown once, as the network row' );

		$add = self::row( $html, '&#039;sha256-abc=&#039;' );
		$this->assertStringStartsWith( 'codo-csp-pending-add|', $add );
		$this->assertStringContainsString( '<span class="codo-csp-badge">in draft</span>', $add );
		$this->assertStringContainsString( 'From a scan', $add );
		$this->assertStringContainsString( '>Remove</button>', $add );

		$remove = self::row( $html, 'data:' );
		$this->assertStringStartsWith( 'codo-csp-pending-remove|', $remove );
		$this->assertStringContainsString( '<span class="codo-csp-badge">removal in draft</span>', $remove );
		$this->assertStringContainsString( 'name="action" value="codo_csp_add_rule"', $remove );
		$this->assertStringContainsString( '>Keep</button>', $remove );

		$this->assertStringContainsString( '<th scope="rowgroup" rowspan="3"><code>img-src</code>', $html );
	}

	public function test_sources_kept_for_a_network_created_directive() {
		Functions\when( 'is_multisite' )->justReturn( true );
		$this->site_options[ PolicyStore::NETWORK_OPTION ] = array(
			'site' => array( self::rule( 'style-src-elem', 'https://fonts.googleapis.com', 'network', 1767225600 ) ),
		);
		$this->policy(
			array(
				self::rule( 'style-src', "'self'" ),
				self::rule( 'style-src', "'unsafe-inline'" ),
			)
		);

		$html = $this->render();

		$this->assertStringContainsString( '<th scope="rowgroup" rowspan="3"><code>style-src-elem</code>', $html );
		$this->assertStringStartsWith( 'codo-csp-network|', self::row( $html, 'https://fonts.googleapis.com' ) );
		$this->assertSame( 2, substr_count( $html, '<tr class="codo-csp-network-inherited">' ) );
		$this->assertSame( 2, substr_count( $html, '<span class="description">Kept because a network default created this directive</span>' ) );
		$this->assertStringContainsString( '<tr class="codo-csp-network-inherited"><td><code>&#039;self&#039;</code></td><td>Inherited (fallback)<br><span class="description">2026-01-01 00:00</span></td><td></td><td><span class="description">Kept because a network default created this directive</span></td></tr>', $html );
		$this->assertStringContainsString( '<tr class="codo-csp-network-inherited"><td><code>&#039;unsafe-inline&#039;</code></td>', $html );
		$this->assertSame( 2, substr_count( $html, 'name="action" value="codo_csp_remove_rule"' ), 'only the two style-src rules can be removed' );
	}

	public function test_network_scope_shows_no_inherited_rows() {
		Functions\when( 'is_multisite' )->justReturn( true );
		$this->site_options[ PolicyStore::NETWORK_OPTION ] = array(
			'site' => array( self::rule( 'style-src-elem', 'https://fonts.googleapis.com', 'network' ) ),
		);

		$html = $this->render( 'site', 'network' );

		$this->assertStringNotContainsString( 'codo-csp-network-inherited', $html );
		$this->assertStringContainsString( '<th scope="rowgroup" rowspan="1"><code>style-src-elem</code>', $html );
	}

	public function test_network_scope_shows_network_rules_as_removable() {
		Functions\when( 'is_multisite' )->justReturn( true );
		$this->site_options[ PolicyStore::NETWORK_OPTION ] = array(
			'login' => array( self::rule( 'font-src', 'https://fonts.network.test', 'network' ) ),
		);

		$html = $this->render( 'login', 'network' );

		$row = self::row( $html, 'https://fonts.network.test' );
		$this->assertStringStartsWith( 'codo-csp-live|', $row );
		$this->assertStringContainsString( 'name="scope" value="network"', $row );
		$this->assertStringContainsString( '>Remove</button>', $row );
		$this->assertStringNotContainsString( 'codo-csp-draft', $html );
		$this->assertStringNotContainsString( '&#039;self&#039;', $html, 'local rules are not shown' );
		$this->assertStringContainsString( 'id="codo-csp-network-login-directive"', $html );
		$this->assertStringContainsString( 'id="codo-csp-preset-network-login"', $html );
	}

	public function test_add_and_presets_forms() {
		$html = $this->render( 'login' );

		$this->assertStringContainsString( '<h2>Add a source</h2><form method="post" action="https://www.example.com/wp-admin/admin-post.php" class="codo-csp-add">', $html );
		$this->assertStringContainsString( '<input type="hidden" name="action" value="codo_csp_add_rule"><input type="hidden" name="context" value="login"><input type="hidden" name="scope" value="site">', $html );
		$this->assertStringContainsString( '<label for="codo-csp-site-login-directive">Directive</label><br><select name="directive" id="codo-csp-site-login-directive">', $html );
		$this->assertStringContainsString( '<option value="script-src">script-src</option>', $html );
		$this->assertStringContainsString( '<option value="frame-ancestors">frame-ancestors</option>', $html );
		$this->assertStringContainsString( 'name="source" id="codo-csp-site-login-source" required', $html );
		$this->assertStringContainsString( 'aria-describedby="codo-csp-site-login-help"', $html );
		$this->assertStringContainsString( 'id="codo-csp-site-login-help"', $html );
		$this->assertStringContainsString( 'name="note" maxlength="200" id="codo-csp-site-login-note"', $html );
		$this->assertStringContainsString( '<button type="submit">Add source</button></form>', $html );

		$this->assertStringContainsString( '<h2>Add a common service</h2>', $html );
		$this->assertStringContainsString( 'class="codo-csp-presets"><input type="hidden" name="action" value="codo_csp_preset">', $html );
		$this->assertStringContainsString( 'value="nonce-codo_csp_preset"', $html );
		$this->assertStringContainsString( '<select name="preset" id="codo-csp-preset-site-login">', $html );
		$this->assertStringContainsString( '<option value="google-fonts">Google Fonts</option>', $html );
		$this->assertStringContainsString( '<option value="stripe">', $html );
		$this->assertStringContainsString( '<button type="submit">Add service</button></p></form>', $html );
	}

	/**
	 * @return array<string, array{0: string, 1: string}>
	 */
	public function origins() {
		return array(
			'default'        => array( 'default', 'Default' ),
			'manual'         => array( 'manual', 'Added by hand' ),
			'scan'           => array( 'scan', 'From a scan' ),
			'report'         => array( 'report', 'From a report' ),
			'inherited'      => array( 'inherited', 'Inherited (fallback)' ),
			'network'        => array( 'network', 'Network default' ),
			'preset'         => array( 'preset:stripe', 'Preset: Stripe (Stripe.js and Checkout)' ),
			'removed preset' => array( 'preset:gone', 'Preset: gone' ),
			'unknown'        => array( 'imported', 'imported' ),
			'empty'          => array( '', '' ),
		);
	}

	/**
	 * @dataProvider origins
	 */
	public function test_origin_label( $origin, $label ) {
		$this->assertSame( $label, PolicyView::origin_label( $origin ) );
	}
}
