<?php
/**
 * Tests for UrlResolver.
 *
 * @package CodoDigital\Csp\Tests
 */

namespace CodoDigital\Csp\Tests\Unit\Scan;

use CodoDigital\Csp\Scan\UrlResolver;
use CodoDigital\Csp\Tests\TestCase;

class UrlResolverTest extends TestCase {

	const BASE = 'https://www.example.com/blog/post/index.html?p=1#top';

	/**
	 * @dataProvider references
	 */
	public function test_resolves( $ref, $expected, $base = self::BASE ) {
		$this->assertSame( $expected, UrlResolver::resolve( $ref, $base ) );
	}

	public function references() {
		return array(
			'absolute'                  => array( 'https://cdn.example.net/a.js?v=1', 'https://cdn.example.net/a.js?v=1' ),
			'absolute other scheme'     => array( 'wss://live.example.net/s', 'wss://live.example.net/s' ),
			'protocol-relative'         => array( '//cdn.example.net/a.js', 'https://cdn.example.net/a.js' ),
			'protocol-relative http'    => array( '//cdn.example.net/a.js', 'http://cdn.example.net/a.js', 'http://www.example.com/' ),
			'root-relative'             => array( '/wp-content/a.css?ver=2#x', 'https://www.example.com/wp-content/a.css?ver=2#x' ),
			'root-relative dots'        => array( '/a/./b/../c.js', 'https://www.example.com/a/c.js' ),
			'root-relative keeps port'  => array( '/x.js', 'http://localhost:8080/x.js', 'http://localhost:8080/wp/' ),
			'relative'                  => array( 'img/a.png', 'https://www.example.com/blog/post/img/a.png' ),
			'relative dot'              => array( './a.png', 'https://www.example.com/blog/post/a.png' ),
			'relative parent'           => array( '../a.png', 'https://www.example.com/blog/a.png' ),
			'relative parents too far'  => array( '../../../../a.png', 'https://www.example.com/a.png' ),
			'relative trailing dotdot'  => array( 'x/..', 'https://www.example.com/blog/post/' ),
			'relative trailing dot'     => array( 'x/.', 'https://www.example.com/blog/post/x/' ),
			'relative with query'       => array( 'a.js?v=1#f', 'https://www.example.com/blog/post/a.js?v=1#f' ),
			'relative from host only'   => array( 'a.js', 'https://www.example.com/a.js', 'https://www.example.com' ),
			'dot from root'             => array( '.', 'https://www.example.com/', 'https://www.example.com/' ),
			'query only'                => array( '?page=2', 'https://www.example.com/blog/post/index.html?page=2' ),
			'query only no base path'   => array( '?page=2', 'https://www.example.com/?page=2', 'https://www.example.com' ),
			'fragment only'             => array( '#section', '' ),
			'empty'                     => array( '', '' ),
			'whitespace'                => array( "  \n ", '' ),
			'javascript'                => array( 'JavaScript:alert(1)', '' ),
			'mailto'                    => array( 'mailto:a@example.com', '' ),
			'about'                     => array( 'about:blank', '' ),
			'tel'                       => array( 'tel:+441234', '' ),
			'sms'                       => array( 'sms:+441234', '' ),
			'data'                      => array( 'data:image/png;base64,AAAA', 'data:' ),
			'blob upper'                => array( 'BLOB:https://www.example.com/uuid', 'blob:' ),
			'html entities'             => array( '/a.js?x=1&amp;y=2', 'https://www.example.com/a.js?x=1&y=2' ),
			'entity encoded javascript' => array( 'javascript&#58;alert(1)', '' ),
			'trimmed'                   => array( '  /a.js  ', 'https://www.example.com/a.js' ),
			'bad base'                  => array( '/a.js', '', 'not a url' ),
			'base without host'         => array( 'a.js', '', 'file:///tmp/x' ),
			'base without scheme'       => array( 'a.js', '', '//www.example.com/' ),
			'absolute ignores bad base' => array( 'https://cdn.example.net/a.js', 'https://cdn.example.net/a.js', '' ),
		);
	}
}
