<?php
/**
 * Class Base64
 *
 * @created      23.06.2023
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2023 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\Authenticator\Common;

use InvalidArgumentException;
use ParagonIE\ConstantTime\Base64 as ConstantTimeBase64;
use SensitiveParameter;
use function function_exists, preg_match;

/**
 * Class to provide base64 encoding/decoding of strings using constant time functions
 */
class Base64 implements EncoderInterface{

	/**
	 * The Base64 character set as defined by RFC3548
	 *
	 * @see https://datatracker.ietf.org/doc/html/rfc3548#section-3
	 * @see https://datatracker.ietf.org/doc/html/rfc4648#section-4
	 */
	public const CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';

	/**
	 * Encode a string to Base64
	 */
	public static function encode(#[SensitiveParameter] string $string):string{

		if(function_exists('sodium_bin2base64')){
			return \sodium_bin2base64($string, \SODIUM_BASE64_VARIANT_ORIGINAL);
		}

		return ConstantTimeBase64::encode($string); // @codeCoverageIgnore
	}

	/**
	 * Decode a string from Base64
	 */
	public static function decode(#[SensitiveParameter] string $encodedString):string{
		self::checkCharacterSet($encodedString);

		if(function_exists('sodium_base642bin')){
			return \sodium_base642bin($encodedString, \SODIUM_BASE64_VARIANT_ORIGINAL);
		}

		return ConstantTimeBase64::decode($encodedString); // @codeCoverageIgnore
	}

	public static function checkCharacterSet(#[SensitiveParameter] string $encodedString):void{

		if(!preg_match('#^[a-z\d/=+]+$#i', $encodedString)){
			throw new InvalidArgumentException('Base64 must match RFC4648 character set');
		}

	}

}
