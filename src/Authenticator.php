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

use foo\bar;

/**
 * Yet another Google authenticator implemetation!
 *
 * @link http://jacob.jkrall.net/totp/
 * @link https://github.com/PHPGangsta/GoogleAuthenticator
 * @link https://github.com/devicenull/PHP-Google-Authenticator
 *
 * @property int $digits
 * @property int $period
 */
class Authenticator{
	use Magic;

	const SECRET_DEFAULT_LENGTH = 16;

	/**
	 * @link https://github.com/google/google-authenticator/wiki/Key-Uri-Format#digits
	 *
	 * @var int
	 */
	protected $digits = 6;

	/**
	 * @link https://github.com/google/google-authenticator/wiki/Key-Uri-Format#period
	 *
	 * @var int
	 */
	protected $period = 30;

	/**
	 * @var \chillerlan\GoogleAuth\Base32
	 */
	protected $base32;

	/**
	 * Authenticator constructor.
	 *
	 * @param int|null $period
	 * @param int|null $digits
	 *
	 * @throws \chillerlan\GoogleAuth\AuthenticatorException
	 */
	public function __construct(int $period = null, int $digits = null){

		if(!is_null($period)){
			$this->setPeriod($period);
		}

		if(!is_null($digits)){
			$this->setDigits($digits);
		}

		$this->base32 = new Base32;

	}

	/**
	 * Sets the code length to either 6 or 8
	 *
	 * @param int $digits
	 *
	 * @return \chillerlan\GoogleAuth\Authenticator
	 * @throws \chillerlan\GoogleAuth\AuthenticatorException
	 */
	public function setDigits(int $digits):Authenticator {

		if(!in_array(intval($digits), [6, 8], true)){
			throw new AuthenticatorException('Invalid code length: '.$digits);
		}

		$this->digits = $digits;

		return $this;
	}

	/**
	 * Sets the period to a value between 10 and 60 seconds
	 *
	 * @param int $period
	 *
	 * @return \chillerlan\GoogleAuth\Authenticator
	 * @throws \chillerlan\GoogleAuth\AuthenticatorException
	 */
	public function setPeriod(int $period):Authenticator {
		$period = intval($period);

		if($period < 15 || $period > 60){
			throw new AuthenticatorException('Invalid period: '.$period);
		}

		$this->period = $period;

		return $this;
	}

	/**
	 * Generates a new (secure random) secret phrase
	 * "an arbitrary key value encoded in Base32 according to RFC 3548"
	 *
	 * @link https://github.com/PHPGangsta/GoogleAuthenticator/pull/10
	 *
	 * @param int $length
	 *
	 * @return string
	 * @throws \chillerlan\GoogleAuth\AuthenticatorException
	 */
	public function createSecret(int $length = null):string {
		$length = !is_null($length)
			? intval($length)
			: self::SECRET_DEFAULT_LENGTH;

		// ~ 80 to 640 bits
		if($length < 16 || $length > 128){
			throw new AuthenticatorException('Invalid secret length: '.$length);
		}

		$random = random_bytes($length);
		$chars  = str_split(Base32::RFC3548);
		$secret = '';

		for($i = 0; $i < $length; $i++){
			$secret .= $chars[ord($random[$i])&31];
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
	public function getCode(string $secret, float $timeslice = null):string {
		// Pack time into binary string
		$time  = str_repeat(chr(0), 4);
		$time .= pack('N*', $this->checkTimeslice($timeslice));

		// Hash it with users secret key
		$hmac = hash_hmac('SHA1', $time, $this->base32->toString($this->checkSecret($secret)), true);

		// Use last nibble of result as index/offset
		$offset = ord(substr($hmac, -1))&0x0F;

		// Unpack binary value, only 32 bits
		$value = unpack('N', substr($hmac, $offset, 4))[1]&0x7FFFFFFF;

		return str_pad($value % pow(10, $this->digits), $this->digits, '0', STR_PAD_LEFT);
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
	public function verifyCode(string $code, string $secret, float $timeslice = null, int $adjacent = 1):bool {

		for($i = -$adjacent; $i <= $adjacent; $i++){
			/**
			 * A timing safe equals comparison
			 * more info here: http://blog.ircmaxell.com/2014/11/its-all-about-time.html
			 */
			if(hash_equals($this->getCode($this->checkSecret($secret), $this->checkTimeslice($timeslice) + $i), $code)){
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
	public function getUri(string $secret, string $label, string $issuer):string {

		// https://github.com/google/google-authenticator/wiki/Key-Uri-Format#parameters
		$values = [
			'secret' => $this->checkSecret($secret),
			'issuer' => $issuer,
		];

		if($this->digits !== 6){
			$values['digits'] = $this->digits;
		}

		if($this->period !== 30){
			$values['period'] = $this->period;
		}

		return 'otpauth://totp/'.$label.'?'.http_build_query($values);
	}

	/**
	 * Checks if the secret phrase matches the character set
	 *
	 * @param string $secret
	 *
	 * @return string
	 * @throws \chillerlan\GoogleAuth\AuthenticatorException
	 */
	protected function checkSecret(string $secret):string {

		if(!(bool)preg_match('/^['.Base32::RFC3548.']+$/', $secret)){
			throw new AuthenticatorException('Invalid secret phrase!');
		}

		return $secret;
	}

	/**
	 * @param float $timeslice
	 *
	 * @return float
	 */
	protected function checkTimeslice(float $timeslice = null):float {

		if(is_null($timeslice)){
			$timeslice = floor(time() / $this->period);
		}

		return $timeslice;
	}

}
