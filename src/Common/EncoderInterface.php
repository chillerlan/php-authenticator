<?php
/**
 * Interface EncoderInterface
 *
 * @created      02.11.2025
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2025 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\Authenticator\Common;

use SensitiveParameter;

/**
 * Common interface for character encoding classes
 */
interface EncoderInterface{

	/**
	 * The allowed character set
	 *
	 * @var string
	 */
	public const CHARSET = '';

	/**
	 * Encode a string
	 */
	public static function encode(#[SensitiveParameter] string $string):string;

	/**
	 * Decode a string
	 */
	public static function decode(#[SensitiveParameter] string $encodedString):string;

	/**
	 * Checks if the given string only contains allowed characters
	 *
	 * @throws \InvalidArgumentException
	 */
	public static function checkCharacterSet(#[SensitiveParameter] string $encodedString):void;

}
