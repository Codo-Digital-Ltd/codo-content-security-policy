<?php
/**
 * Tests for Source.
 *
 * @package CodoDigital\Csp\Tests
 */

namespace CodoDigital\Csp\Tests\Unit\Policy;

use CodoDigital\Csp\Policy\InvalidSourceException;
use CodoDigital\Csp\Policy\Source;
use CodoDigital\Csp\Tests\TestCase;

class SourceTest extends TestCase {

	/**
	 * @dataProvider valid_sources
	 */
	public function test_normalises_valid_sources( $directive, $raw, $expected ) {
		$this->assertSame( $expected, Source::normalise( $directive, $raw ) );
	}

	public function valid_sources() {
		return array(
			'quoted keyword'          => array( 'script-src', "'self'", "'self'" ),
			'bare keyword'            => array( 'script-src', 'SELF', "'self'" ),
			'none'                    => array( 'object-src', 'none', "'none'" ),
			'unsafe-inline in script' => array( 'script-src', 'unsafe-inline', "'unsafe-inline'" ),
			'unsafe-inline in style'  => array( 'style-src-attr', "'unsafe-inline'", "'unsafe-inline'" ),
			'unsafe-eval in default'  => array( 'default-src', "'unsafe-eval'", "'unsafe-eval'" ),
			'hash'                    => array( 'script-src', "'SHA256-abc+/=='", "'sha256-abc+/=='" ),
			'bare hash'               => array( 'style-src', 'sha384-abc_-', "'sha384-abc_-'" ),
			'scheme'                  => array( 'img-src', 'DATA:', 'data:' ),
			'https scheme in img-src' => array( 'img-src', 'https:', 'https:' ),
			'host'                    => array( 'img-src', 'CDN.Example.com', 'cdn.example.com' ),
			'wildcard host'           => array( 'img-src', '*.example.com', '*.example.com' ),
			'star in img-src'         => array( 'img-src', '*', '*' ),
			'host with scheme'        => array( 'script-src', 'https://cdn.example.com', 'https://cdn.example.com' ),
			'default port dropped'    => array( 'script-src', 'https://cdn.example.com:443', 'https://cdn.example.com' ),
			'custom port kept'        => array( 'connect-src', 'wss://live.example.com:8443', 'wss://live.example.com:8443' ),
			'wildcard port'           => array( 'connect-src', 'example.com:*', 'example.com:*' ),
			'pasted url keeps path'   => array( 'script-src', 'https://cdn.example.com/lib/app.js?ver=1#x', 'https://cdn.example.com/lib/app.js' ),
			'trailing slash dropped'  => array( 'script-src', 'https://cdn.example.com/', 'https://cdn.example.com' ),
			'ip host'                 => array( 'connect-src', 'http://127.0.0.1:8080', 'http://127.0.0.1:8080' ),
			'frame-ancestors self'    => array( 'frame-ancestors', "'self'", "'self'" ),
			'blob: in worker-src'     => array( 'worker-src', 'blob:', 'blob:' ),
			'self in worker-src'      => array( 'worker-src', 'self', "'self'" ),
			'wildcard sub in script'  => array( 'script-src', 'https://*.example.com', 'https://*.example.com' ),
			'star host in img-src'    => array( 'img-src', 'https://*', 'https://*' ),
			'star port in img-src'    => array( 'img-src', '*:*', '*:*' ),
			'blob: in img-src'        => array( 'img-src', 'blob:', 'blob:' ),
			'data: in frame-src'      => array( 'frame-src', 'data:', 'data:' ),
			'https: in connect-src'   => array( 'connect-src', 'https:', 'https:' ),
			'host in base-uri'        => array( 'base-uri', 'https://www.example.com', 'https://www.example.com' ),
		);
	}

	/**
	 * @dataProvider invalid_sources
	 */
	public function test_rejects_invalid_or_unsafe_sources( $directive, $raw ) {
		$this->expectException( InvalidSourceException::class );
		Source::normalise( $directive, $raw );
	}

	public function invalid_sources() {
		return array(
			'unknown directive'           => array( 'sandbox', "'self'" ),
			'empty'                       => array( 'img-src', '   ' ),
			'two values'                  => array( 'img-src', 'a.com b.com' ),
			'semicolon injection'         => array( 'img-src', "a.com; script-src *" ),
			'comma'                       => array( 'img-src', 'a.com,b.com' ),
			'newline injection'           => array( 'img-src', "a.com\nX-Evil: 1" ),
			'quote'                       => array( 'img-src', 'a"b.com' ),
			'too long'                    => array( 'img-src', str_repeat( 'a', 256 ) ),
			'nonce'                       => array( 'script-src', "'nonce-abc'" ),
			'unknown keyword'             => array( 'script-src', "'unsafe-everything'" ),
			'hash outside script/style'   => array( 'img-src', "'sha256-abc'" ),
			'script keyword in img-src'   => array( 'img-src', "'unsafe-inline'" ),
			'eval in style-src'           => array( 'style-src', "'unsafe-eval'" ),
			'strict-dynamic in style'     => array( 'style-src', "'strict-dynamic'" ),
			'star in script-src'          => array( 'script-src', '*' ),
			'https: in script-src'        => array( 'script-src', 'https:' ),
			'data: in script-src-elem'    => array( 'script-src-elem', 'data:' ),
			'blob: in object-src'         => array( 'object-src', 'blob:' ),
			'https: in base-uri'          => array( 'base-uri', 'https:' ),
			'javascript: in img-src'      => array( 'img-src', 'javascript:' ),
			'star in default-src'         => array( 'default-src', '*' ),
			'https: in default-src'       => array( 'default-src', 'https:' ),
			'blob: in default-src'        => array( 'default-src', 'blob:' ),
			'blob: in script-src'         => array( 'script-src', 'blob:' ),
			'http: in script-src-attr'    => array( 'script-src-attr', 'http:' ),
			'filesystem: in base-uri'     => array( 'base-uri', 'filesystem:' ),
			'javascript: in script-src'   => array( 'script-src', 'javascript:' ),
			'star host in script-src'     => array( 'script-src', 'https://*' ),
			'star host and port'          => array( 'script-src', '*:*' ),
			'star host with port, path'   => array( 'object-src', 'http://*:8080/x' ),
			'star host path in base-uri'  => array( 'base-uri', '*/path' ),
			'star host in default-src'    => array( 'default-src', 'wss://*' ),
			'star host in worker-src'     => array( 'worker-src', 'https://*' ),
			'star in worker-src'          => array( 'worker-src', '*' ),
			'data: in worker-src'         => array( 'worker-src', 'data:' ),
			'https: in worker-src'        => array( 'worker-src', 'https:' ),
			'unsafe-inline in worker-src' => array( 'worker-src', "'unsafe-inline'" ),
			'bad host'                    => array( 'img-src', '-bad-.com' ),
			'bad port'                    => array( 'img-src', 'example.com:70000' ),
			'port zero'                   => array( 'img-src', 'example.com:0' ),
			'unicode host'                => array( 'img-src', 'exämple.com' ),
		);
	}

	public function test_identifies_hashes_and_inline_cancelling_sources() {
		$this->assertTrue( Source::is_hash( "'sha512-abc'" ) );
		$this->assertFalse( Source::is_hash( "'self'" ) );
		$this->assertTrue( Source::cancels_unsafe_inline( "'sha256-abc'" ) );
		$this->assertTrue( Source::cancels_unsafe_inline( "'strict-dynamic'" ) );
		$this->assertTrue( Source::cancels_unsafe_inline( "'nonce-abc'" ) );
		$this->assertFalse( Source::cancels_unsafe_inline( "'unsafe-eval'" ) );
	}

	public function test_too_broad_message_names_source_and_directive() {
		try {
			Source::normalise( 'script-src', 'HTTPS://*' );
			$this->fail( 'Expected an exception.' );
		} catch ( InvalidSourceException $e ) {
			$this->assertSame( 'https://* in script-src would let a script be loaded from anywhere, which defeats the policy. Add the specific host instead.', $e->getMessage() );
		}
	}

	/**
	 * @dataProvider meaningful_cases
	 */
	public function test_is_meaningful( $directive, $source, $expected ) {
		$this->assertSame( $expected, Source::is_meaningful( $directive, $source ) );
	}

	public function meaningful_cases() {
		return array(
			'host anywhere'                => array( 'img-src', 'https://a.example.com', true ),
			'self anywhere'                => array( 'worker-src', "'self'", true ),
			'none anywhere'                => array( 'img-src', "'none'", true ),
			'unsafe-inline in script'      => array( 'script-src-elem', "'unsafe-inline'", true ),
			'unsafe-inline in style'       => array( 'style-src', "'unsafe-inline'", true ),
			'unsafe-inline in worker-src'  => array( 'worker-src', "'unsafe-inline'", false ),
			'unsafe-eval in worker-src'    => array( 'worker-src', "'unsafe-eval'", false ),
			'unsafe-inline in img-src'     => array( 'img-src', "'unsafe-inline'", false ),
			'unsafe-eval in style'         => array( 'style-src', "'unsafe-eval'", false ),
			'hash in script'               => array( 'script-src', "'sha256-abc'", true ),
			'hash in style'                => array( 'style-src-elem', "'sha256-abc'", true ),
			'hash in worker-src'           => array( 'worker-src', "'sha256-abc'", false ),
			'hash in img-src'              => array( 'img-src', "'sha256-abc'", false ),
			'strict-dynamic in default'    => array( 'default-src', "'strict-dynamic'", true ),
		);
	}

	/**
	 * @dataProvider scheme_cases
	 */
	public function test_scheme_matches( $expected, $actual, $result ) {
		$this->assertSame( $result, Source::scheme_matches( $expected, $actual ) );
	}

	public function scheme_cases() {
		return array(
			'http http'    => array( 'http', 'http', true ),
			'http https'   => array( 'http', 'https', true ),
			'http ws'      => array( 'http', 'ws', false ),
			'https https'  => array( 'https', 'https', true ),
			'https http'   => array( 'https', 'http', false ),
			'https wss'    => array( 'https', 'wss', false ),
			'ws ws'        => array( 'ws', 'ws', true ),
			'ws wss'       => array( 'ws', 'wss', true ),
			'ws http'      => array( 'ws', 'http', true ),
			'ws https'     => array( 'ws', 'https', true ),
			'wss wss'      => array( 'wss', 'wss', true ),
			'wss https'    => array( 'wss', 'https', true ),
			'wss ws'       => array( 'wss', 'ws', false ),
			'wss http'     => array( 'wss', 'http', false ),
			'data data'    => array( 'data', 'data', true ),
			'data blob'    => array( 'data', 'blob', false ),
			'custom exact' => array( 'ftp', 'ftp', true ),
		);
	}

	public function test_warnings() {
		$this->assertNotSame( '', Source::warning( 'script-src', "'unsafe-eval'" ) );
		$this->assertNotSame( '', Source::warning( 'script-src', "'unsafe-inline'" ) );
		$this->assertSame( '', Source::warning( 'style-src', "'unsafe-inline'" ) );
		$this->assertNotSame( '', Source::warning( 'img-src', 'https:' ) );
		$this->assertSame( '', Source::warning( 'img-src', 'https://a.com' ) );
	}

	/**
	 * @dataProvider match_cases
	 */
	public function test_matches( $source, $url, $page, $expected ) {
		$this->assertSame( $expected, Source::matches( $source, $url, $page ) );
	}

	public function match_cases() {
		$https = 'https://www.example.com';
		$http  = 'http://www.example.com';
		return array(
			'self same origin'                => array( "'self'", 'https://www.example.com/a.js', $https, true ),
			'self other host'                 => array( "'self'", 'https://cdn.example.com/a.js', $https, false ),
			'self other port'                 => array( "'self'", 'https://www.example.com:8443/a.js', $https, false ),
			'self http page https resource'   => array( "'self'", 'https://www.example.com/a.js', $http, true ),
			'self https page http resource'   => array( "'self'", 'http://www.example.com/a.js', $https, false ),
			'self with bad page origin'       => array( "'self'", 'https://www.example.com/a.js', 'nonsense', false ),
			'self never matches data'         => array( "'self'", 'data:', $https, false ),
			'other keyword never matches'     => array( "'unsafe-inline'", 'https://www.example.com/a.js', $https, false ),
			'unparseable url'                 => array( '*', 'not a url', $https, false ),
			'scheme data'                     => array( 'data:', 'data:', $https, true ),
			'scheme https'                    => array( 'https:', 'https://x.org/', $https, true ),
			'scheme http upgrades'            => array( 'http:', 'https://x.org/', $https, true ),
			'scheme ws upgrades'              => array( 'ws:', 'wss://x.org/', $https, true ),
			'scheme mismatch'                 => array( 'https:', 'http://x.org/', $https, false ),
			'star any https'                  => array( '*', 'https://x.org/', $https, true ),
			'star not data'                   => array( '*', 'data:', $https, false ),
			'host not data'                   => array( 'cdn.example.com', 'data:', $https, false ),
			'host exact'                      => array( 'cdn.example.com', 'https://cdn.example.com/x', $https, true ),
			'host other'                      => array( 'cdn.example.com', 'https://evil.com/x', $https, false ),
			'host suffix trick'               => array( 'example.com', 'https://evilexample.com/x', $https, false ),
			'schemeless host https page http' => array( 'cdn.example.com', 'http://cdn.example.com/x', $https, false ),
			'schemeless host http page http'  => array( 'cdn.example.com', 'http://cdn.example.com/x', $http, true ),
			'schemeless with bad page'        => array( 'cdn.example.com', 'https://cdn.example.com/x', 'bad', true ),
			'host with scheme'                => array( 'https://cdn.example.com', 'https://cdn.example.com/x', $https, true ),
			'host with http scheme upgrades'  => array( 'http://cdn.example.com', 'https://cdn.example.com/x', $https, true ),
			'host scheme mismatch'            => array( 'https://cdn.example.com', 'wss://cdn.example.com/x', $https, false ),
			'wildcard subdomain'              => array( '*.example.com', 'https://a.b.example.com/x', $https, true ),
			'wildcard not apex'               => array( '*.example.com', 'https://example.com/x', $https, false ),
			'wildcard suffix trick'           => array( '*.example.com', 'https://badexample.com/x', $https, false ),
			'star host with scheme'           => array( 'https://*', 'https://any.org/x', $https, true ),
			'default port required'           => array( 'cdn.example.com', 'https://cdn.example.com:8443/x', $https, false ),
			'explicit port'                   => array( 'https://cdn.example.com:8443', 'https://cdn.example.com:8443/x', $https, true ),
			'explicit port mismatch'          => array( 'https://cdn.example.com:8443', 'https://cdn.example.com/x', $https, false ),
			'wildcard port'                   => array( 'cdn.example.com:*', 'https://cdn.example.com:9999/x', $https, true ),
			'http source port upgraded'       => array( 'http://cdn.example.com', 'https://cdn.example.com:443/x', $https, true ),
			'directory path'                  => array( 'https://cdn.example.com/lib/', 'https://cdn.example.com/lib/a.js', $https, true ),
			'directory path outside'          => array( 'https://cdn.example.com/lib/', 'https://cdn.example.com/other/a.js', $https, false ),
			'exact path'                      => array( 'https://cdn.example.com/lib/a.js', 'https://cdn.example.com/lib/a.js', $https, true ),
			'exact path other file'           => array( 'https://cdn.example.com/lib/a.js', 'https://cdn.example.com/lib/b.js', $https, false ),
			'malformed host source'           => array( 'https://', 'https://cdn.example.com/x', $https, false ),
			'self wss on https page'          => array( "'self'", 'wss://www.example.com/socket', $https, true ),
			'self ws on https page'           => array( "'self'", 'ws://www.example.com/socket', $https, false ),
			'self ws on http page'            => array( "'self'", 'ws://www.example.com/socket', $http, true ),
			'self wss on http page'           => array( "'self'", 'wss://www.example.com/socket', $http, true ),
			'self explicit default port'      => array( "'self'", 'https://www.example.com:443/a.js', $https, true ),
			'self http page default ports'    => array( "'self'", 'wss://www.example.com/s', $http, true ),
			'self custom page port'           => array( "'self'", 'http://www.example.com:8080/a.js', 'http://www.example.com:8080', true ),
			'self custom port, other scheme'  => array( "'self'", 'https://www.example.com/a.js', 'http://www.example.com:8080', false ),
			'self custom port, default page'  => array( "'self'", 'https://www.example.com:8080/a.js', $https, false ),
			'self unknown page scheme'        => array( "'self'", 'ftp://www.example.com/x', 'ftp://www.example.com', true ),
			'self unknown page scheme https'  => array( "'self'", 'https://www.example.com/x', 'ftp://www.example.com', false ),
			'scheme ws matches https'         => array( 'ws:', 'https://x.org/', $https, true ),
			'scheme wss matches https'        => array( 'wss:', 'https://x.org/', $https, true ),
			'scheme wss not http'             => array( 'wss:', 'http://x.org/', $https, false ),
			'scheme http not ws'              => array( 'http:', 'ws://x.org/', $https, false ),
			'scheme https not wss'            => array( 'https:', 'wss://x.org/', $https, false ),
			'host wss matches https'          => array( 'wss://live.example.com', 'https://live.example.com/x', $https, true ),
			'host ws matches wss'             => array( 'ws://live.example.com', 'wss://live.example.com/x', $https, true ),
			'host https not wss'              => array( 'https://live.example.com', 'wss://live.example.com/x', $https, false ),
			'schemeless host on http page ws' => array( 'live.example.com', 'ws://live.example.com/x', $http, false ),
		);
	}

	public function test_parse_and_origin() {
		$this->assertNull( Source::parse( 'nonsense' ) );
		$this->assertNull( Source::parse( 'https:///nohost' ) );
		$this->assertSame( 'data', Source::parse( 'data:image/png;base64,xx' )['scheme'] );
		$this->assertSame( '/', Source::parse( 'https://a.com' )['path'] );
		$this->assertNull( Source::parse( 'gopher://a.com' )['port'] );

		$this->assertSame( 'https://a.com', Source::origin_of( 'https://A.com:443/x?y' ) );
		$this->assertSame( 'https://a.com:8443', Source::origin_of( 'https://a.com:8443/x' ) );
		$this->assertSame( 'data:', Source::origin_of( 'data:image/png;base64,xx' ) );
		$this->assertSame( 'gopher://a.com:70', Source::origin_of( 'gopher://a.com:70/' ) );
		$this->assertNull( Source::origin_of( 'nonsense' ) );
	}
}
