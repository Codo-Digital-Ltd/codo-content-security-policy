<?php
/**
 * Tests for NetworkPage.
 *
 * @package CodoDigital\Csp\Tests
 */

namespace CodoDigital\Csp\Tests\Unit\Admin;

use Brain\Monkey\Functions;
use CodoDigital\Csp\Admin\NetworkPage;
use CodoDigital\Csp\Settings\PolicyStore;

class NetworkPageTest extends AdminTestCase {

	protected function setUp(): void {
		parent::setUp();
		$this->boot();
		Functions\when( 'is_multisite' )->justReturn( true );
		$this->can = array( 'manage_network_options' );
	}

	private function page() {
		return new NetworkPage( $this->store, $this->notices );
	}

	private function render() {
		ob_start();
		$this->page()->render();
		return ob_get_clean();
	}

	public function test_register() {
		$page = $this->page();
		$page->register();
		$this->assertNotFalse( has_action( 'network_admin_menu', array( $page, 'add_menu' ) ) );
	}

	public function test_add_menu_under_network_settings() {
		$page = $this->page();
		Functions\expect( 'add_submenu_page' )->once()->with( 'settings.php', 'Content Security Policy', 'Content Security Policy', 'manage_network_options', 'codo-csp-network', array( $page, 'render' ) );
		$page->add_menu();
	}

	public function test_render_requires_the_network_capability() {
		$this->can = array( 'manage_options' );
		$this->expectException( \RuntimeException::class );
		$this->expectExceptionMessage( 'wp_die: You do not have permission to view this page.' );
		$this->page()->render();
	}

	public function test_render_site_tab() {
		$this->site_options[ PolicyStore::NETWORK_OPTION ] = array(
			'site'  => array( self::rule( 'img-src', 'https://cdn.network.test', 'network' ) ),
			'login' => array( self::rule( 'font-src', 'https://fonts.network.test', 'network' ) ),
		);
		$this->notices->add( 'success', 'Done.' );

		$html = $this->render();

		$this->assertStringContainsString( 'Content Security Policy: network defaults', $html );
		$this->assertStringContainsString( '<p>Done.</p>', $html );
		$this->assertStringContainsString( 'settings.php?page=codo-csp-network&tab=site" class="nav-tab nav-tab-active">Front end', $html );
		$this->assertStringContainsString( 'settings.php?page=codo-csp-network&tab=login" class="nav-tab">Login page', $html );
		$this->assertStringContainsString( 'https://cdn.network.test', $html );
		$this->assertStringNotContainsString( 'https://fonts.network.test', $html );
		$this->assertStringContainsString( 'name="scope" value="network"', $html );
		$this->assertStringContainsString( 'name="context" value="site"', $html );
		$this->assertStringNotContainsString( "'unsafe-inline'", html_entity_decode( $html, ENT_QUOTES ), 'site rules are not shown' );
		$this->assertStringContainsString( 'Removing a network default takes effect straight away', $html );
	}

	public function test_render_login_tab() {
		$this->site_options[ PolicyStore::NETWORK_OPTION ] = array(
			'login' => array( self::rule( 'font-src', 'https://fonts.network.test', 'network' ) ),
		);
		$_GET['tab'] = 'login';

		$html = $this->render();

		$this->assertStringContainsString( 'tab=login" class="nav-tab nav-tab-active">Login page', $html );
		$this->assertStringContainsString( 'https://fonts.network.test', $html );
		$this->assertStringContainsString( 'name="context" value="login"', $html );
	}

	public function test_unknown_tab_is_the_site_tab() {
		$_GET['tab'] = array( 'login' );
		$this->assertStringContainsString( 'tab=site" class="nav-tab nav-tab-active"', $this->render() );
	}
}
