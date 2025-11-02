<?php
/**
 * Class Hex
 *
 * @created      28.06.2023
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2023 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\Authenticator\Common;

use InvalidArgumentException;
use ParagonIE\ConstantTime\Hex as ConstantTimeHex;
use SensitiveParameter;
use function function_exists, preg_match;

/**
 * Class to provide hexadecimal encoding/decoding of strings using constant time functions
 *
 * (class is currently unused)
 */
class Hex implements EncoderInterface{

	public const CHARSET = '1234567890ABCDEFabcdef';

	/**
	 * Encode a string to hexadecimal
	 */
	public static function encode(#[SensitiveParameter] string $string):string{

		if(function_exists('sodium_bin2hex')){
			return \sodium_bin2hex($string);
		}

		return ConstantTimeHex::encode($string);
	}

	/**
	 * Decode a string from hexadecimal
	 */
	public static function decode(#[SensitiveParameter] string $encodedString):string{
		self::checkCharacterSet($encodedString);

		if(function_exists('sodium_hex2bin')){
			return \sodium_hex2bin($encodedString);
		}

		return ConstantTimeHex::decode($encodedString);
	}

	public static function checkCharacterSet(#[SensitiveParameter] string $encodedString):void{

		if(!preg_match('#^[a-f\d]+$#i', $encodedString)){
			throw new InvalidArgumentException('hex string must match hexadecimal character set: 0-9, A-F, a-f');
		}

	}

}
