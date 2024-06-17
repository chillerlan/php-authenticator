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
use function preg_match;

/**
 *
 */
class Hex{

	/**
	 * The allowed hex character set (either upper or lower case)
	 *
	 * @var string
	 */
	public const CHARSET = '1234567890ABCDEFabcdef';

	/**
	 * Encode a string to hexadecimal
	 *
	 * @codeCoverageIgnore
	 */
	public static function encode(#[SensitiveParameter] string $str):string{

		if(function_exists('sodium_bin2hex')){
			return \sodium_bin2hex($str);
		}

		return ConstantTimeHex::encode($str);
	}

	/**
	 * Decode a string from hexadecimal
	 *
	 * @codeCoverageIgnore
	 */
	public static function decode(#[SensitiveParameter] string $hex):string{
		self::checkCharacterSet($hex);

		if(function_exists('sodium_hex2bin')){
			return \sodium_hex2bin($hex);
		}

		return ConstantTimeHex::decode($hex);
	}

	/**
	 * @throws \InvalidArgumentException
	 */
	public static function checkCharacterSet(#[SensitiveParameter] string $hex):void{

		if(!preg_match('#^[a-f\d]+$#i', $hex)){
			throw new InvalidArgumentException('hex string must match hexadecimal character set: 0-9, A-F, a-f');
		}

	}

}
