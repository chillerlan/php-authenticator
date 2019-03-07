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

use chillerlan\Settings\SettingsContainerInterface;

/**
 * Yet another Google authenticator implementation!
 *
 * @link https://tools.ietf.org/html/rfc4226
 * @link https://tools.ietf.org/html/rfc6238
 * @link https://github.com/google/google-authenticator
 * @link https://openauthentication.org/specifications-technical-resources/
 * @link http://blog.ircmaxell.com/2014/11/its-all-about-time.html
 */
class Authenticator{

	/**
	 * the decoded secret phrase
	 *
	 * @var string
	 */
	protected $secret;

	/**
	 * @var \chillerlan\Authenticator\AuthenticatorOptions
	 */
	protected $options;

	/**
	 * @var \chillerlan\Authenticator\Base32
	 */
	protected $base32;

	/**
	 * Authenticator constructor.
	 *
	 * @param \chillerlan\Settings\SettingsContainerInterface|null $options
	 * @param string|null                                          $secret
	 *
	 * @throws \chillerlan\Authenticator\AuthenticatorException
	 */
	public function __construct(SettingsContainerInterface $options = null, string $secret = null){

		if(PHP_INT_SIZE < 8){
			throw new AuthenticatorException('64bit php required'); // @codeCoverageIgnore
		}

		$this->base32 = new Base32;

		$this->setOptions($options ?? new AuthenticatorOptions);

		if($secret !== null){
			$this->setSecret($secret);
		}

	}

	/**
	 * @param \chillerlan\Settings\SettingsContainerInterface $options
	 *
	 * @return \chillerlan\Authenticator\Authenticator
	 */
	public function setOptions(SettingsContainerInterface $options):Authenticator{
		$this->options = $options;

		return $this;
	}

	/**
	 * @param string $secret
	 *
	 * @return \chillerlan\Authenticator\Authenticator
	 */
	public function setSecret(string $secret):Authenticator{

		if(!preg_match('/^['.Base32::RFC3548.']+$/', $secret)){
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
	 * Generates a new (secure random) secret phrase
	 * "an arbitrary key value encoded in Base32 according to RFC 3548"

	 * @param int $length
	 *
	 * @return string
	 * @throws \chillerlan\Authenticator\AuthenticatorException
	 */
	public function createSecret(int $length = null):string{
		$length = intval($length ?? $this->options->secret_length);

		// ~ 80 to 640 bits
		if($length < 16){
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
	public function timeslice(int $timestamp = null):int{
		return (int)floor(($timestamp ?? time()) / $this->options->period);
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

		if($this->options->mode === 'hotp'){
			$data = $data ?? 0;

			$hashdata = pack('NN', ($data & 0xFFFFFFFF00000000) >> 32, $data & 0x00000000FFFFFFFF);
		}
		else{
			$hashdata = pack('J', $data ?? $this->timeslice());
		}

		$hash = hash_hmac($this->options->algorithm, $hashdata, $this->secret, true);
		$code = unpack('N', substr($hash, ord(substr($hash, -1)) & 0xF, 4))[1] & 0x7FFFFFFF;

		// test values
		// HOTP: https://tools.ietf.org/html/rfc4226#page-32
		// TOTP: https://tools.ietf.org/html/rfc6238#page-14
#		var_dump(['data' => dechex($data), 'hash' => bin2hex($hash), 'truncated_hex' => dechex($code), 'truncated_int' => $code]);

		return str_pad($code % pow(10, $this->options->digits), $this->options->digits, '0', STR_PAD_LEFT);
	}

	/**
	 * Checks the given $code against the secret and accepts $adjacent codes for $data
	 *  - a UNIX timestamp (TOTP)
	 *  - a counter value (HOTP)
	 *
	 * @param string $code
	 * @param int    $data
	 *
	 * @return bool
	 */
	public function verify(string $code, int $data = null):bool{

		if($this->options->mode === 'hotp'){
			if(hash_equals($this->code($data ?? 0), $code)){
				return true;
			}
		}
		else{
			$timeslice = $this->timeslice($data);

			for($i = -$this->options->adjacent; $i <= $this->options->adjacent; $i++){
				if(hash_equals($this->code($timeslice + $i), $code)){
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Creates an URI for use in QR codes for example
	 *
	 * @link https://github.com/google/google-authenticator/wiki/Key-Uri-Format#parameters
	 *
	 * @param string   $label
	 * @param string   $issuer
	 * @param int|null $hotpCounter
	 *
	 * @return string
	 */
	public function getUri(string $label, string $issuer, int $hotpCounter = null):string{

		$values = [
			'secret'    => $this->getSecret(),
			'issuer'    => $issuer,
			'digits'    => $this->options->digits,
			'algorithm' => $this->options->algorithm,
		];

		if($this->options->mode === 'totp'){
			$values['period'] = $this->options->period;
		}

		if($this->options->mode === 'hotp' && $hotpCounter !== null){
			$values['counter'] = $hotpCounter;
		}

		return 'otpauth://'.$this->options->mode.'/'.rawurlencode($label).'?'.http_build_query($values, '', '&', PHP_QUERY_RFC3986);
	}

}
