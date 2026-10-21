<?php
/**
 * Thrown when a source expression is invalid or unsafe for its directive.
 *
 * @package CodoDigital\Csp
 */

namespace CodoDigital\Csp\Policy;

defined( 'ABSPATH' ) || exit;

/**
 * Invalid source expression. The message is translated and safe to show
 * (escaped) to administrators.
 */
class InvalidSourceException extends \InvalidArgumentException {
}
