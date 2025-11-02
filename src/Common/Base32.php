<?php
/**
 * Class Base32
 *
 * @created      23.06.2023
 * @author       Smiley <smiley@chillerlan.net>
 * @copyright    2023 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\Authenticator\Common;

use InvalidArgumentException;
use ParagonIE\ConstantTime\Base32 as ConstantTimeBase32;
use SensitiveParameter;
use function preg_match;

/**
 * Class to provide base32 encoding/decoding of strings using constant time functions
 */
final class Base32 implements EncoderInterface{

	/**
	 * The Base32 character set as defined by RFC3548
	 *
	 * @see https://datatracker.ietf.org/doc/html/rfc3548#section-5
	 * @see https://datatracker.ietf.org/doc/html/rfc4648#section-6
	 */
	public const CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * Encode a string to Base32
	 */
	public static function encode(#[SensitiveParameter] string $string):string{
		return ConstantTimeBase32::encodeUpperUnpadded($string);
	}

	/**
	 * Decode a string from Base32
	 */
	public static function decode(#[SensitiveParameter] string $encodedString):string{
		self::checkCharacterSet($encodedString);

		return ConstantTimeBase32::decodeNoPadding($encodedString, true);
	}

	public static function checkCharacterSet(#[SensitiveParameter] string $encodedString):void{

		if(!preg_match('/^['.self::CHARSET.']+$/', $encodedString)){
			throw new InvalidArgumentException('Base32 must match RFC3548 character set');
		}

	}

}
