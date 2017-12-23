<?php
/**
 * Class Authenticator
 *
 * @filesource   Authenticator.php
 * @created      24.11.2015
 * @package      chillerlan\Authenticator
 * @author       Smiley <smiley@chillerlan.net>
 * @copyright    2015 Smiley
 * @license      MIT
 */

namespace chillerlan\Authenticator;

/**
 * Yet another Google authenticator implementation!
 *
 * @link https://tools.ietf.org/html/rfc4226
 * @link https://tools.ietf.org/html/rfc6238
 * @link https://github.com/google/google-authenticator
 * @link https://openauthentication.org/specifications-technical-resources/
 * @link http://blog.ircmaxell.com/2014/11/its-all-about-time.html -> todo
 */
class Authenticator{

	const DEFAULT_DIGITS        = 6;
	const DEFAULT_PERIOD        = 30;
	const DEFAULT_SECRET_LENGTH = 20;
	const DEFAULT_HASH_ALGO     = 'SHA1';
	const DEFAULT_AUTH_MODE     = 'totp';

	/**
	 * @var int
	 */
	protected $digits = self::DEFAULT_DIGITS;

	/**
	 * @var int
	 */
	protected $period = self::DEFAULT_PERIOD;

	/**
	 * SHA1, SHA256, SHA512
	 *
	 * @var string
	 */
	protected $algorithm = self::DEFAULT_HASH_ALGO;

	/**
	 * totp, hotp
	 *
	 * @var string
	 */
	protected $mode = self::DEFAULT_AUTH_MODE;

	/**
	 * the decoded secret phrase
	 *
	 * @var string
	 */
	protected $secret;

	/**
	 * current HOTP counter value
	 *
	 * @var int
	 */
	protected $counter;

	/**
	 * @var \chillerlan\Authenticator\Base32
	 */
	protected $base32;

	/**
	 * Authenticator constructor.
	 */
	public function __construct(){

		if(PHP_INT_SIZE < 8){
			throw new AuthenticatorException('64bit php required'); // @codeCoverageIgnore
		}

		$this->base32 = new Base32;
	}

	/**
	 * Sets the code length to either 6 or 8
	 *
	 * @param int $digits
	 *
	 * @return \chillerlan\Authenticator\Authenticator
	 * @throws \chillerlan\Authenticator\AuthenticatorException
	 */
	public function setDigits(int $digits):Authenticator{

		if(!in_array(intval($digits), range(6, 8), true)){
			throw new AuthenticatorException('Invalid code length: '.$digits);
		}

		$this->digits = $digits;

		return $this;
	}

	/**
	 * @return int
	 */
	public function getDigits():int{
		return $this->digits;
	}

	/**
	 * Sets the period to a value between 10 and 60 seconds
	 *
	 * @param int $period
	 *
	 * @return \chillerlan\Authenticator\Authenticator
	 * @throws \chillerlan\Authenticator\AuthenticatorException
	 */
	public function setPeriod(int $period):Authenticator{
		$p = intval($period);

		if($p < 15 || $p > 60){
			throw new AuthenticatorException('Invalid period: '.$p);
		}

		$this->period = $p;

		return $this;
	}

	/**
	 * @return int
	 */
	public function getPeriod():int{
		return $this->period;
	}

	/**
	 * @param string $algorithm
	 *
	 * @return \chillerlan\Authenticator\Authenticator
	 * @throws \chillerlan\Authenticator\AuthenticatorException
	 */
	public function setAlgorithm(string $algorithm):Authenticator{
		$this->algorithm = strtoupper($algorithm);

		if(!in_array($this->algorithm, ['SHA1', 'SHA256', 'SHA512'], true)){
			throw new AuthenticatorException('Invalid algorithm: '.$this->algorithm);
		}

		return $this;
	}

	/**
	 * @return string
	 */
	public function getAlgorithm():string{
		return $this->algorithm;
	}

	/**
	 * @param string $mode
	 *
	 * @return \chillerlan\Authenticator\Authenticator
	 * @throws \chillerlan\Authenticator\AuthenticatorException
	 */
	public function setMode(string $mode):Authenticator{
		$this->mode = strtolower($mode);

		if(!in_array($this->mode, ['totp', 'hotp'], true)){
			throw new AuthenticatorException('Invalid algorithm: '.$mode);
		}

		return $this;
	}

	/**
	 * @return string
	 */
	public function getMode():string{
		return $this->mode;
	}

	/**
	 * @param string $secret
	 *
	 * @return \chillerlan\Authenticator\Authenticator
	 */
	public function setSecret(string $secret):Authenticator{

		if(!preg_match('/^['.$this->base32::RFC3548.']+$/', $secret)){
			throw new AuthenticatorException('Invalid secret phrase');
		}

		$this->secret = $this->base32->toString($secret);

		return $this;
	}

	/**
	 * @return string
	 */
	public function getSecret():string{
		return $this->base32->fromString($this->secret);
	}

	/**
	 * @return int
	 */
	public function getCounter():int {
		return $this->counter ?? 0;
	}

	/**
	 * Generates a new (secure random) secret phrase
	 * "an arbitrary key value encoded in Base32 according to RFC 3548"

	 * @param int $length
	 *
	 * @return string
	 * @throws \chillerlan\Authenticator\AuthenticatorException
	 */
	public function createSecret(int $length = null):string{
		$length = intval($length ?? $this::DEFAULT_SECRET_LENGTH);

		// ~ 80 to 640 bits
		if($length < 16 || $length > 128){
			throw new AuthenticatorException('Invalid secret length: '.$length);
		}

		$this->secret = random_bytes($length);

		return $this->getSecret();
	}

	/**
	 * @param int|null $timestamp
	 *
	 * @return int
	 */
	public function timeslice(int $timestamp = null):int {
		return (int)floor(($timestamp ?? time()) / $this->period);
	}

	/**
	 * @param int|null $timeslice
	 *
	 * @return string
	 */
	protected function totp_data(int $timeslice = null):string{
		return pack('J', $timeslice ?? $this->timeslice());
	}

	/**
	 * @param int|null $counter
	 *
	 * @return string
	 */
	protected function hotp_data(int $counter = null):string{
		$this->counter = intval($counter ?? $this->counter ?? 0);

		return pack('NN', ($this->counter & 0xFFFFFFFF00000000) >> 32, $this->counter & 0x00000000FFFFFFFF);
	}

	/**
	 * $data may be
	 *  - a UNIX timestamp (TOTP)
	 *  - a counter value (HOTP)
	 *
	 * @param int|null $data
	 *
	 * @return string
	 */
	public function code(int $data = null):string{
		$hash = hash_hmac($this->algorithm, call_user_func_array([$this, $this->mode.'_data'], [$data]), $this->secret, true);
		$code = unpack('N', substr($hash, ord(substr($hash, -1)) & 0xF, 4))[1] & 0x7FFFFFFF;

		// test values
		// HOTP: https://tools.ietf.org/html/rfc4226#page-32
		// TOTP: https://tools.ietf.org/html/rfc6238#page-14
#		var_dump(['data' => dechex($data), 'hash' => bin2hex($hash), 'truncated_hex' => dechex($code), 'truncated_int' => $code]);

		return str_pad($code % pow(10, $this->digits), $this->digits, '0', STR_PAD_LEFT);
	}

	/**
	 * @param string $code
	 * @param int    $counter
	 * @param int    $adjacent
	 *
	 * @return bool
	 */
	protected function hotp_verify(string $code, int $counter = null, int $adjacent):bool{
		$counter = intval($counter ?? $this->counter ?? 0);

		for($i = $counter - $adjacent; $i <= $counter + $adjacent; $i++){
			if(hash_equals($this->code($i), $code)){
				$this->counter = $counter+1;

				return true;
			}
		}

		return false;
	}

	/**
	 * @param string $code
	 * @param int    $timestamp
	 * @param int    $adjacent
	 *
	 * @return bool
	 */
	protected function totp_verify(string $code, int $timestamp = null, int $adjacent):bool{
		$timeslice = $this->timeslice($timestamp);

		for($i = -$adjacent; $i <= $adjacent; $i++){
			if(hash_equals($this->code($timeslice + $i), $code)){
				return true;
			}
		}

		return false;
	}

	/**
	 * Checks the given $code against the secret and accepts $adjacent codes for $data
	 *  - a UNIX timestamp (TOTP)
	 *  - a counter value (HOTP)
	 *
	 * @param string $code
	 * @param int    $data
	 * @param int    $adjacent
	 *
	 * @return bool
	 */
	public function verify(string $code, int $data = null, int $adjacent = null):bool{
		return call_user_func_array([$this, $this->mode.'_verify'], [$code, $data, $adjacent ?? 1]);
	}

	/**
	 * Creates an URI for use in QR codes for example
	 *
	 * @link https://github.com/google/google-authenticator/wiki/Key-Uri-Format#parameters
	 *
	 * @param string $label
	 * @param string $issuer
	 *
	 * @return string
	 */
	public function getUri(string $label, string $issuer):string{

		$values = [
			'secret' => $this->getSecret(),
			'issuer' => $issuer,
			'digits' => $this->digits,
		];

		if($this->mode === 'totp'){
			$values['period'] = $this->period;
		}

		if($this->mode === 'hotp'){
			$values['counter'] = $this->counter;
		}

		$values['algorithm'] = $this->algorithm;

		return 'otpauth://'.$this->mode.'/'.rawurlencode($label).'?'.http_build_query($values, '', '&', PHP_QUERY_RFC3986);
	}

}
