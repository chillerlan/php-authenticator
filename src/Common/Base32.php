<?php
/**
 * Class Base32
 *
 * @created      23.06.2023
 * @author       Smiley <smiley@chillerlan.net>
 * @copyright    2023 smiley
 * @license      MIT
 */

namespace chillerlan\Authenticator\Common;

use InvalidArgumentException;
use ParagonIE\ConstantTime\Base32 as ConstantTimeBase32;
use TypeError;
use function is_string;
use function preg_match;

/**
 * Class to provide base32 encoding/decoding of strings using constant time functions
 */
final class Base32{

	/**
	 * The Base32 character set as defined by RFC3548
	 *
	 * @see https://datatracker.ietf.org/doc/html/rfc3548#section-5
	 * @see https://datatracker.ietf.org/doc/html/rfc4648#section-6
	 *
	 * @var string
	 */
	const CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * Encode a string to Base32
	 *
	 * @param string $str
	 *
	 * @return string
	 */
	public static function encode($str){
		return ConstantTimeBase32::encodeUpperUnpadded($str);
	}

	/**
	 * Decode a string from Base32
	 *
	 * @param string $base32
	 *
	 * @return string
	 */
	public static function decode($base32){
		self::checkCharacterSet($base32);

		return ConstantTimeBase32::decodeUpper($base32);
	}

	/**
	 * @return void
	 * @throws \InvalidArgumentException
	 */
	public static function checkCharacterSet($base32){

		if(!is_string($base32)){
			throw new TypeError('$base32 is expected to be string'); // @codeCoverageIgnore
		}

		if(!preg_match('/^['.self::CHARSET.']+$/', $base32)){
			throw new InvalidArgumentException('Base32 must match RFC3548 character set');
		}

	}

}
