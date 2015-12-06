<?php
/**
 * Class Authenticator
 *
 * @link         https://github.com/google/google-authenticator
 *
 * @filesource   Authenticator.php
 * @created      24.11.2015
 * @package      chillerlan\GoogleAuth
 * @author       Smiley <smiley@chillerlan.net>
 * @copyright    2015 Smiley
 * @license      MIT
 */

namespace chillerlan\GoogleAuth;

use chillerlan\Base32\Base32;

/**
 * Yet another Google authenticator implemetation!
 *
 * @link http://jacob.jkrall.net/totp/
 * @link https://github.com/PHPGangsta/GoogleAuthenticator
 * @link https://github.com/devicenull/PHP-Google-Authenticator
 */
class Authenticator{

	/**
	 * @link https://github.com/google/google-authenticator/wiki/Key-Uri-Format#digits
	 *
	 * @var int
	 */
	public static $digits = 6;

	/**
	 * @link https://github.com/google/google-authenticator/wiki/Key-Uri-Format#period
	 *
	 * @var int
	 */
	public static $period = 30;

	/**
	 * Sets the code length to either 6 or 8
	 *
	 * @param int $digits
	 *
	 * @throws \chillerlan\GoogleAuth\AuthenticatorException
	 */
	public static function setDigits($digits = 6){

		if(!in_array($digits, [6, 8], true)){
			throw new AuthenticatorException('Invalid code length: '.$digits);
		}

		self::$digits = $digits;
	}

	/**
	 * Sets the period to a value between 10 and 60 seconds
	 *
	 * @param int $period
	 *
	 * @throws \chillerlan\GoogleAuth\AuthenticatorException
	 */
	public static function setPeriod($period = 30){

		if(!is_int($period) || $period < 15 || $period > 60){ // for cereal?
			throw new AuthenticatorException('Invalid period: '.$period);
		}

		self::$period = $period;
	}

	/**
	 * Generates a new secret phrase
	 * "an arbitrary key value encoded in Base32 according to RFC 3548"
	 *
	 * @param int $secretLength
	 *
	 * @return string
	 * @throws \chillerlan\GoogleAuth\AuthenticatorException
	 */
	public static function createSecret($secretLength = 16){
		if(!is_int($secretLength) || $secretLength < 1){
			throw new AuthenticatorException('Invalid secret length!');
		}

		$chars = str_split(Base32::RFC3548);
		$secret = '';

		for($i = 0; $i < $secretLength; $i++){
			$secret .= $chars[array_rand($chars)];
		}

		return $secret;
	}

	/**
	 * Calculate the code with the given secret and point in time
	 *
	 * @param string $secret
	 * @param float  $timeslice -> floor($timestamp / 30)
	 *
	 * @return string
	 * @throws \chillerlan\GoogleAuth\AuthenticatorException
	 */
	public static function getCode($secret, $timeslice = null){

		if(!preg_match('/^['.Base32::RFC3548.']+$/', $secret)){
			throw new AuthenticatorException('Invalid secret phrase!');
		}

		if($timeslice === null || !is_float($timeslice)){
			$timeslice = floor(time() / self::$period);
		}

		// Pack time into binary string
		$time = str_repeat(chr(0), 4).pack('N*', $timeslice);
		// Hash it with users secret key
		$hmac = hash_hmac('SHA1', $time, Base32::toString($secret), true);
		// Use last nibble of result as index/offset
		$offset = ord(substr($hmac, -1))&0x0F;
		// Unpack binary value, only 32 bits
		$value = unpack('N', substr($hmac, $offset, 4))[1]&0x7FFFFFFF;

		return str_pad($value % pow(10, self::$digits), self::$digits, '0', STR_PAD_LEFT);
	}

	/**
	 * Checks the given code against the secret with a given point in time and accepting adjacent codes
	 *
	 * @param string $code
	 * @param string $secret
	 * @param float  $timeslice -> floor($timestamp / 30)
	 * @param int    $adjacent
	 *
	 * @return bool
	 * @throws \chillerlan\GoogleAuth\AuthenticatorException
	 */
	public static function verifyCode($code, $secret, $timeslice = null, $adjacent = 1){

		if(!preg_match('/^['.Base32::RFC3548.']+$/', $secret)){
			throw new AuthenticatorException('Invalid secret phrase!');
		}

		if($timeslice === null || !is_float($timeslice)){
			$timeslice = floor(time() / self::$period);
		}

		for($i = -$adjacent; $i <= $adjacent; $i++){
			if($code === self::getCode($secret, $timeslice + $i)){
				return true;
			}
		}

		return false;
	}

	/**
	 * Creates an URI for use in QR codes for example
	 *
	 * @param string $secret
	 * @param string $label
	 * @param string $issuer
	 *
	 * @return string
	 * @throws \chillerlan\GoogleAuth\AuthenticatorException
	 */
	public static function getUri($secret, $label, $issuer){

		if(!preg_match('/^['.Base32::RFC3548.']+$/', $secret)){
			throw new AuthenticatorException('Invalid secret phrase!');
		}

		// https://github.com/google/google-authenticator/wiki/Key-Uri-Format#parameters
		$values = [
			'secret' => $secret,
			'issuer' => $issuer,
#			'algorithm' => 'SHA1',
		];

		if(self::$digits !== 6){
			$values['digits'] = self::$digits;
		}

		if(self::$period !== 30){
			$values['period'] = self::$period;
		}

		return 'otpauth://totp/'.$label.'?'.http_build_query($values);
	}

	/**
	 * Generates an URL to the Google (deprecated) charts QR code API.
	 *
	 * @link       https://github.com/codemasher/php-qrcode/
	 * @deprecated https://developers.google.com/chart/infographics/docs/qr_codes
	 *
	 * @param string $secret
	 * @param string $label
	 * @param string $issuer
	 *
	 * @return string
	 */
	public static function getGoogleQr($secret, $label, $issuer) {

		$query = [
			'chs'  => '200x200',
			'chld' => 'M|0',
			'cht'  => 'qr',
			'chl'  => self::getUri($secret, $label, $issuer),
		];

		return 'https://chart.googleapis.com/chart?'.http_build_query($query);
	}

}
