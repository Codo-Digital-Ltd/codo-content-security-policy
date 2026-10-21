<?php
/**
 * Tests for HtmlParser.
 *
 * @package CodoDigital\Csp\Tests
 */

namespace CodoDigital\Csp\Tests\Unit\Scan;

use CodoDigital\Csp\Scan\HtmlParser;
use CodoDigital\Csp\Tests\TestCase;

class HtmlParserTest extends TestCase {

	const PAGE = 'https://www.example.com/blog/post/';

	/**
	 * Parse a body fragment.
	 *
	 * @param string $body HTML inside <body>.
	 * @param string $head HTML inside <head>.
	 * @return array<string, mixed>
	 */
	private function parse( $body, $head = '' ) {
		return ( new HtmlParser() )->parse_html( '<!doctype html><html><head>' . $head . '</head><body>' . $body . '</body></html>', self::PAGE );
	}

	/**
	 * Resources as "directive url" strings.
	 *
	 * @param array<int, array{directive: string, url: string}> $resources Resources.
	 * @return string[]
	 */
	private static function flat( array $resources ) {
		return array_map(
			static function ( $r ) {
				return $r['directive'] . ' ' . $r['url'];
			},
			$resources
		);
	}

	public function test_empty_html() {
		$result = ( new HtmlParser() )->parse_html( "  \n", self::PAGE );
		$this->assertSame( array(), $result['resources'] );
		$this->assertSame( array(), $result['stylesheets'] );
		$this->assertSame(
			array(
				'script-src-elem' => 0,
				'script-src-attr' => 0,
				'style-src-elem'  => 0,
				'style-src-attr'  => 0,
			),
			$result['inline']
		);
	}

	public function test_scripts() {
		$result = $this->parse(
			'<script src="https://cdn.example.net/a.js"></script>'
			. '<script src="/local.js?ver=1"></script>'
			. '<script>console.log(1)</script>'
			. '<script>   </script>'
			. '<script type="module">import "./x.js";</script>'
			. '<script type="application/ld+json">{"@context":"https://schema.org"}</script>'
			. '<script type=" IMPORTMAP ">{}</script>'
			. '<script type="speculationrules" src="/rules.json"></script>'
			. '<script type="text/template"><div></div></script>'
		);
		$this->assertSame(
			array( 'script-src-elem https://cdn.example.net/a.js', 'script-src-elem https://www.example.com/local.js?ver=1' ),
			self::flat( $result['resources'] )
		);
		$this->assertSame( 2, $result['inline']['script-src-elem'] );
	}

	public function test_event_handlers_and_javascript_urls_count_as_attr_scripts() {
		$result = $this->parse(
			'<button onclick="go()">Go</button>'
			. '<body onload="x()"></body>'
			. '<a href="javascript:void(0)">x</a>'
			. '<a href="  JAVASCRIPT:alert(1)">x</a>'
			. '<form action="javascript:x()"><button formaction="javascript:y()">b</button></form>'
			. '<iframe src="javascript:false"></iframe>'
			. '<div on="x" data-onclick="y">not handlers</div>'
			. '<a href="/page">normal</a>'
		);
		$this->assertSame( 6, $result['inline']['script-src-attr'] );
		// A javascript: form action resolves to nothing; the iframe src too.
		$this->assertSame( array(), $result['resources'] );
	}

	public function test_style_attributes_and_elements() {
		$result = $this->parse(
			'<div style="color:red"></div>'
			. '<div style="   "></div>'
			. '<div style="background:url(\'/img/bg.png\')"></div>'
			. '<style>body{background:url(texture.jpg)}</style>'
			. '<style> </style>',
			'<style>@font-face{src:url("/fonts/a.woff2") format("woff2")}</style>'
		);
		$this->assertSame( 2, $result['inline']['style-src-attr'] );
		$this->assertSame( 2, $result['inline']['style-src-elem'] );
		$this->assertEqualsCanonicalizing(
			array(
				'img-src https://www.example.com/img/bg.png',
				'img-src https://www.example.com/blog/post/texture.jpg',
				'font-src https://www.example.com/fonts/a.woff2',
			),
			self::flat( $result['resources'] )
		);
	}

	public function test_links() {
		$result = $this->parse(
			'',
			'<link rel="stylesheet" href="/style.css">'
			. '<link rel="Alternate  Stylesheet" href="https://cdn.example.net/alt.css">'
			. '<link rel="stylesheet" href="javascript:x">'
			. '<link rel="stylesheet">'
			. '<link rel="icon" href="/favicon.ico">'
			. '<link rel="shortcut icon" href="/s.ico">'
			. '<link rel="apple-touch-icon" href="/touch.png">'
			. '<link rel="mask-icon" href="/mask.svg">'
			. '<link rel="manifest" href="/site.webmanifest">'
			. '<link rel="preload" as="font" href="/f.woff2" crossorigin>'
			. '<link rel="preload" as="script" href="/p.js">'
			. '<link rel="preload" as="style" href="/p.css">'
			. '<link rel="preload" as="image" href="/p.png">'
			. '<link rel="preload" as="fetch" href="/api/data">'
			. '<link rel="preload" as="audio" href="/p.mp3">'
			. '<link rel="preload" as="video" href="/p.mp4">'
			. '<link rel="preload" as="document" href="/ignored.html">'
			. '<link rel="preload" href="/no-as">'
			. '<link rel="modulepreload" href="/m.js">'
			. '<link rel="modulepreload" as="style" href="/m2.js">'
			. '<link rel="canonical" href="/canonical">'
			. '<link rel="preconnect" href="https://fonts.gstatic.com">'
		);
		$this->assertSame(
			array(
				'style-src-elem https://www.example.com/style.css',
				'style-src-elem https://cdn.example.net/alt.css',
				'img-src https://www.example.com/favicon.ico',
				'img-src https://www.example.com/s.ico',
				'img-src https://www.example.com/touch.png',
				'img-src https://www.example.com/mask.svg',
				'manifest-src https://www.example.com/site.webmanifest',
				'font-src https://www.example.com/f.woff2',
				'script-src-elem https://www.example.com/p.js',
				'style-src-elem https://www.example.com/p.css',
				'img-src https://www.example.com/p.png',
				'connect-src https://www.example.com/api/data',
				'media-src https://www.example.com/p.mp3',
				'media-src https://www.example.com/p.mp4',
				'script-src-elem https://www.example.com/m.js',
				'script-src-elem https://www.example.com/m2.js',
			),
			self::flat( $result['resources'] )
		);
		$this->assertSame( array( 'https://www.example.com/style.css', 'https://cdn.example.net/alt.css' ), $result['stylesheets'] );
	}

	public function test_images_and_media() {
		$result = $this->parse(
			'<img src="a.png" srcset="b.png 1x, https://cdn.example.net/c.png 2x,  , d.png">'
			. '<img alt="no src">'
			. '<picture><source srcset="/p.webp" type="image/webp"><img src="/p.jpg"></picture>'
			. '<video src="/v.mp4" poster="/poster.jpg"><source src="/v.webm"><track src="/captions.vtt"></video>'
			. '<audio src="/a.mp3"><source src="/a.ogg"></audio>'
			. '<video></video>'
			. '<input type="image" src="/button.png">'
			. '<input type="text" src="/ignored.png">'
			. '<input src="/also-ignored.png">'
		);
		$this->assertSame(
			array(
				'img-src https://www.example.com/blog/post/a.png',
				'img-src https://www.example.com/blog/post/b.png',
				'img-src https://cdn.example.net/c.png',
				'img-src https://www.example.com/blog/post/d.png',
				'img-src https://www.example.com/p.webp',
				'img-src https://www.example.com/p.jpg',
				'media-src https://www.example.com/v.mp4',
				'img-src https://www.example.com/poster.jpg',
				'media-src https://www.example.com/v.webm',
				'media-src https://www.example.com/captions.vtt',
				'media-src https://www.example.com/a.mp3',
				'media-src https://www.example.com/a.ogg',
				'img-src https://www.example.com/button.png',
			),
			self::flat( $result['resources'] )
		);
	}

	public function test_frames_objects_and_forms() {
		$result = $this->parse(
			'<iframe src="https://www.youtube.com/embed/x"></iframe>'
			. '<iframe></iframe>'
			. '<frame src="/frame.html">'
			. '<object data="/movie.swf"></object>'
			. '<object></object>'
			. '<embed src="/plugin.swf">'
			. '<embed>'
			. '<form action="https://checkout.example.net/pay"></form>'
			. '<form></form>'
			. '<form action="  "></form>'
		);
		$this->assertSame(
			array(
				'frame-src https://www.youtube.com/embed/x',
				'frame-src https://www.example.com/frame.html',
				'object-src https://www.example.com/movie.swf',
				'object-src https://www.example.com/plugin.swf',
				'form-action https://checkout.example.net/pay',
				'form-action https://www.example.com/blog/post/',
			),
			self::flat( $result['resources'] )
		);
	}

	public function test_frame_in_frameset() {
		$result = ( new HtmlParser() )->parse_html( '<html><frameset><frame src="/frame.html"></frameset></html>', self::PAGE );
		$this->assertSame( array( 'frame-src https://www.example.com/frame.html' ), self::flat( $result['resources'] ) );
	}

	public function test_base_href_changes_relative_resolution() {
		$result = $this->parse(
			'<img src="a.png"><form></form>',
			'<base target="_blank"><base href="https://static.example.com/assets/"><base href="/ignored/">'
		);
		$this->assertSame(
			array(
				'img-src https://static.example.com/assets/a.png',
				// A form without action still posts to the page itself.
				'form-action https://www.example.com/blog/post/',
			),
			self::flat( $result['resources'] )
		);
	}

	public function test_relative_base_href() {
		$result = $this->parse( '<img src="a.png">', '<base href="../media/">' );
		$this->assertSame( array( 'img-src https://www.example.com/blog/media/a.png' ), self::flat( $result['resources'] ) );
	}

	public function test_duplicates_are_removed() {
		$result = $this->parse( '<img src="/a.png"><img src="/a.png"><img src="https://www.example.com/a.png"><video poster="/a.png"></video><iframe src="/a.png"></iframe>' );
		$this->assertSame(
			array( 'img-src https://www.example.com/a.png', 'frame-src https://www.example.com/a.png' ),
			self::flat( $result['resources'] )
		);
	}

	public function test_data_and_entities() {
		$result = $this->parse( '<img src="data:image/png;base64,AAAA"><img src="/x.png?a=1&amp;b=2">' );
		$this->assertSame(
			array( 'img-src data:', 'img-src https://www.example.com/x.png?a=1&b=2' ),
			self::flat( $result['resources'] )
		);
	}

	public function test_utf8_and_malformed_html_do_not_break_parsing() {
		$result = ( new HtmlParser() )->parse_html( '<p>Café ünïcödé<div><img src="/é.png"><span></p></div><script src="/x.js"', self::PAGE );
		$this->assertContains( 'img-src https://www.example.com/é.png', self::flat( $result['resources'] ) );
	}

	public function test_parse_css() {
		$css = <<<'CSS'
/* url(/commented.png) @import "/commented.css"; */
@import url("https://fonts.googleapis.com/css2?family=Inter");
@import 'theme.css';
@import "/print.css" print;
@font-face { src: url( '../fonts/a.woff2' ) format('woff2'), url(../fonts/a.TTF?v=1#iefix) format('truetype'); }
body { background: url( "img/bg.png" ); }
.a { background: url(); mask: url(#mask); filter: url( '#f' ); }
.b { background-image: url(data:image/svg+xml;base64,AAAA); }
.c { cursor: url("https://cdn.example.net/c.cur"), auto; }
.d { background: url(img/bg.png); }
CSS;
		$resources = ( new HtmlParser() )->parse_css( $css, 'https://www.example.com/wp-content/themes/t/style.css' );
		$this->assertSame(
			array(
				'style-src-elem https://fonts.googleapis.com/css2?family=Inter',
				'style-src-elem https://www.example.com/wp-content/themes/t/theme.css',
				'style-src-elem https://www.example.com/print.css',
				'font-src https://www.example.com/wp-content/themes/fonts/a.woff2',
				'font-src https://www.example.com/wp-content/themes/fonts/a.TTF?v=1#iefix',
				'img-src https://www.example.com/wp-content/themes/t/img/bg.png',
				'img-src data:',
				'img-src https://cdn.example.net/c.cur',
			),
			self::flat( $resources )
		);
	}

	public function test_parse_css_drops_unresolvable_urls() {
		$resources = ( new HtmlParser() )->parse_css( '.a{background:url(javascript:x)} .b{background:url(/x.png)}', 'not a url' );
		$this->assertSame( array(), $resources );
	}

	public function test_parse_css_empty() {
		$this->assertSame( array(), ( new HtmlParser() )->parse_css( '', 'https://www.example.com/a.css' ) );
	}

	public function test_css_urls_reports_through_callback() {
		$seen = array();
		( new HtmlParser() )->css_urls(
			'@font-face{src:url(/f.otf)} .x{background:url(/a.gif)}',
			'https://www.example.com/',
			static function ( $directive, $raw ) use ( &$seen ) {
				$seen[] = $directive . ' ' . $raw;
				return $raw;
			}
		);
		$this->assertSame( array( 'font-src /f.otf', 'img-src /a.gif' ), $seen );
	}
}
