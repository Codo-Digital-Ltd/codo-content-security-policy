<?php
/**
 * Finds the resources an HTML page or stylesheet loads.
 *
 * @package CodoDigital\Csp
 */

namespace CodoDigital\Csp\Scan;

defined( 'ABSPATH' ) || exit;

// phpcs:disable WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- DOM properties (tagName, textContent, parentNode).

/**
 * Extracts resource URLs, with the directive each is checked against, and
 * counts inline code. Resources added later by JavaScript (tag managers,
 * chat widgets) cannot be seen here; violation reports catch those.
 */
class HtmlParser {

	const FONT_EXTENSIONS = array( 'woff2', 'woff', 'ttf', 'otf', 'eot' );

	/**
	 * Script types that are data, not code.
	 */
	const DATA_SCRIPT_TYPES = array( 'application/ld+json', 'application/json', 'text/template', 'text/html', 'text/x-template', 'importmap', 'speculationrules', 'text/x-handlebars-template', 'text/plain' );

	/**
	 * Parse an HTML document.
	 *
	 * @param string $html     HTML.
	 * @param string $page_url URL of the page (base for relative URLs).
	 * @return array{resources: array<int, array{directive: string, url: string}>, inline: array<string, int>, stylesheets: string[]}
	 */
	public function parse_html( $html, $page_url ) {
		$result = array(
			'resources'   => array(),
			'inline'      => array(
				'script-src-elem' => 0,
				'script-src-attr' => 0,
				'style-src-elem'  => 0,
				'style-src-attr'  => 0,
			),
			'stylesheets' => array(),
		);
		if ( '' === trim( (string) $html ) ) {
			return $result;
		}

		$doc      = new \DOMDocument();
		$previous = libxml_use_internal_errors( true );
		$doc->loadHTML( '<?xml encoding="UTF-8">' . $html, LIBXML_NONET | LIBXML_NOERROR | LIBXML_NOWARNING );
		libxml_clear_errors();
		libxml_use_internal_errors( $previous );

		$base = $page_url;
		foreach ( $doc->getElementsByTagName( 'base' ) as $element ) {
			if ( $element->hasAttribute( 'href' ) ) {
				$base = UrlResolver::resolve( $element->getAttribute( 'href' ), $page_url );
				break;
			}
		}

		$add = static function ( $directive, $raw ) use ( &$result, $base ) {
			$url = UrlResolver::resolve( $raw, $base );
			if ( '' !== $url ) {
				$result['resources'][] = array(
					'directive' => $directive,
					'url'       => $url,
				);
			}
			return $url;
		};

		foreach ( $doc->getElementsByTagName( '*' ) as $element ) {
			/** Element. @var \DOMElement $element */
			$tag = strtolower( $element->tagName );

			foreach ( $element->attributes as $attribute ) {
				$name = strtolower( $attribute->name );
				if ( 0 === strpos( $name, 'on' ) && strlen( $name ) > 2 ) {
					++$result['inline']['script-src-attr'];
				} elseif ( 'style' === $name && '' !== trim( $attribute->value ) ) {
					++$result['inline']['style-src-attr'];
					$this->css_urls( $attribute->value, $base, $add );
				} elseif ( in_array( $name, array( 'href', 'src', 'action', 'formaction' ), true ) && preg_match( '/^\s*javascript:/i', $attribute->value ) ) {
					++$result['inline']['script-src-attr'];
				}
			}

			switch ( $tag ) {
				case 'script':
					$type = strtolower( trim( $element->getAttribute( 'type' ) ) );
					if ( in_array( $type, self::DATA_SCRIPT_TYPES, true ) ) {
						break;
					}
					if ( $element->hasAttribute( 'src' ) ) {
						$add( 'script-src-elem', $element->getAttribute( 'src' ) );
					} elseif ( '' !== trim( $element->textContent ) ) {
						++$result['inline']['script-src-elem'];
					}
					break;

				case 'link':
					$this->link( $element, $add, $result );
					break;

				case 'style':
					if ( '' !== trim( $element->textContent ) ) {
						++$result['inline']['style-src-elem'];
						$this->css_urls( $element->textContent, $base, $add );
					}
					break;

				case 'img':
				case 'source':
				case 'input':
					$directive = 'img-src';
					if ( 'source' === $tag && $element->parentNode instanceof \DOMElement && in_array( strtolower( $element->parentNode->tagName ), array( 'video', 'audio' ), true ) ) {
						$directive = 'media-src';
					}
					if ( 'input' === $tag && 'image' !== strtolower( $element->getAttribute( 'type' ) ) ) {
						break;
					}
					if ( $element->hasAttribute( 'src' ) ) {
						$add( $directive, $element->getAttribute( 'src' ) );
					}
					foreach ( $this->srcset( $element->getAttribute( 'srcset' ) ) as $candidate ) {
						$add( $directive, $candidate );
					}
					break;

				case 'video':
				case 'audio':
				case 'track':
					if ( $element->hasAttribute( 'src' ) ) {
						$add( 'media-src', $element->getAttribute( 'src' ) );
					}
					if ( $element->hasAttribute( 'poster' ) ) {
						$add( 'img-src', $element->getAttribute( 'poster' ) );
					}
					break;

				case 'iframe':
				case 'frame':
					if ( $element->hasAttribute( 'src' ) ) {
						$add( 'frame-src', $element->getAttribute( 'src' ) );
					}
					break;

				case 'object':
					if ( $element->hasAttribute( 'data' ) ) {
						$add( 'object-src', $element->getAttribute( 'data' ) );
					}
					break;

				case 'embed':
					if ( $element->hasAttribute( 'src' ) ) {
						$add( 'object-src', $element->getAttribute( 'src' ) );
					}
					break;

				case 'form':
					// A form without action submits to the page itself.
					$add( 'form-action', $element->hasAttribute( 'action' ) && '' !== trim( $element->getAttribute( 'action' ) ) ? $element->getAttribute( 'action' ) : $page_url );
					break;
			}
		}

		$result['resources'] = $this->unique( $result['resources'] );
		return $result;
	}

	/**
	 * Handle a link element.
	 *
	 * @param \DOMElement          $element Element.
	 * @param callable             $add     Adds a resource.
	 * @param array<string, mixed> $result  Result (stylesheets are recorded).
	 * @return void
	 */
	private function link( \DOMElement $element, callable $add, array &$result ) {
		if ( ! $element->hasAttribute( 'href' ) ) {
			return;
		}
		$rel  = preg_split( '/\s+/', strtolower( trim( $element->getAttribute( 'rel' ) ) ) );
		$href = $element->getAttribute( 'href' );

		if ( in_array( 'stylesheet', $rel, true ) ) {
			$url = $add( 'style-src-elem', $href );
			if ( '' !== $url ) {
				$result['stylesheets'][] = $url;
			}
		} elseif ( array_intersect( $rel, array( 'icon', 'apple-touch-icon', 'shortcut', 'mask-icon' ) ) ) {
			$add( 'img-src', $href );
		} elseif ( in_array( 'manifest', $rel, true ) ) {
			$add( 'manifest-src', $href );
		} elseif ( array_intersect( $rel, array( 'preload', 'modulepreload' ) ) ) {
			$map = array(
				'script' => 'script-src-elem',
				'style'  => 'style-src-elem',
				'font'   => 'font-src',
				'image'  => 'img-src',
				'fetch'  => 'connect-src',
				'audio'  => 'media-src',
				'video'  => 'media-src',
			);
			$as  = strtolower( $element->getAttribute( 'as' ) );
			if ( in_array( 'modulepreload', $rel, true ) ) {
				$as = 'script';
			}
			if ( isset( $map[ $as ] ) ) {
				$add( $map[ $as ], $href );
			}
		}
	}

	/**
	 * Find url() and @import references in CSS.
	 *
	 * @param string   $css  CSS.
	 * @param string   $base Base URL.
	 * @param callable $add  Adds a resource.
	 * @return void
	 */
	public function css_urls( $css, $base, callable $add ) {
		$css = (string) preg_replace( '~/\*.*?\*/~s', '', (string) $css );

		if ( preg_match_all( '~@import\s+(?:url\(\s*)?["\']?([^"\')\s;]+)~i', $css, $imports ) ) {
			foreach ( $imports[1] as $import ) {
				$add( 'style-src-elem', $import );
			}
		}

		// Font files are fonts wherever they appear (in practice, @font-face src).
		if ( preg_match_all( '~(?<!@import\s)url\(\s*(["\']?)([^"\')]+)\1\s*\)~i', $css, $matches ) ) {
			foreach ( $matches[2] as $url ) {
				$url = trim( $url );
				if ( '' === $url || '#' === $url[0] ) {
					continue;
				}
				$path      = (string) wp_parse_url( $url, PHP_URL_PATH );
				$extension = strtolower( pathinfo( $path, PATHINFO_EXTENSION ) );
				$add( in_array( $extension, self::FONT_EXTENSIONS, true ) ? 'font-src' : 'img-src', $url );
			}
		}
	}

	/**
	 * Parse a stylesheet's references.
	 *
	 * @param string $css CSS.
	 * @param string $url Stylesheet URL (base for relative URLs).
	 * @return array<int, array{directive: string, url: string}>
	 */
	public function parse_css( $css, $url ) {
		$resources = array();
		$this->css_urls(
			$css,
			$url,
			static function ( $directive, $raw ) use ( &$resources, $url ) {
				$resolved = UrlResolver::resolve( $raw, $url );
				if ( '' !== $resolved ) {
					$resources[] = array(
						'directive' => $directive,
						'url'       => $resolved,
					);
				}
				return $resolved;
			}
		);
		return $this->unique( $resources );
	}

	/**
	 * URLs from a srcset attribute.
	 *
	 * @param string $srcset Attribute value.
	 * @return string[]
	 */
	private function srcset( $srcset ) {
		$urls = array();
		foreach ( explode( ',', (string) $srcset ) as $candidate ) {
			$parts = preg_split( '/\s+/', trim( $candidate ) );
			if ( ! empty( $parts[0] ) ) {
				$urls[] = $parts[0];
			}
		}
		return $urls;
	}

	/**
	 * Remove duplicate resources.
	 *
	 * @param array<int, array{directive: string, url: string}> $resources Resources.
	 * @return array<int, array{directive: string, url: string}>
	 */
	private function unique( array $resources ) {
		$seen   = array();
		$unique = array();
		foreach ( $resources as $resource ) {
			$key = $resource['directive'] . ' ' . $resource['url'];
			if ( ! isset( $seen[ $key ] ) ) {
				$seen[ $key ] = true;
				$unique[]     = $resource;
			}
		}
		return $unique;
	}
}
