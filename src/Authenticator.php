<?php
/**
 * Class Authenticator
 *
 * @created      24.11.2015
 * @author       Smiley <smiley@chillerlan.net>
 * @copyright    2015 Smiley
 * @license      MIT
 */

namespace chillerlan\Authenticator;

use chillerlan\Authenticator\Authenticators\AuthenticatorInterface;
use InvalidArgumentException;
use TypeError;
use function array_keys;
use function array_replace;
use function http_build_query;
use function is_string;
use function rawurlencode;
use function sprintf;
use function strtolower;
use function trim;
use const PHP_QUERY_RFC3986;

/**
 * Yet another Google authenticator implementation!
 *
 * @link https://tools.ietf.org/html/rfc4226
 * @link https://tools.ietf.org/html/rfc6238
 * @link https://github.com/google/google-authenticator
 * @link https://openauthentication.org/specifications-technical-resources/
 * @link https://blog.ircmaxell.com/2014/11/its-all-about-time.html
 */
class Authenticator{

	const DEFAULTS = [
		/**
		 * Authenticator mode:
		 *
		 *   - `AuthenticatorInterface::HOTP`  = counter based
		 *   - `AuthenticatorInterface::TOTP`  = time based
		 *   - `AuthenticatorInterface::STEAM` = time based (Steam Guard)
		 *
		 * @type string
		 */
		'mode'          => AuthenticatorInterface::TOTP,

		/**
		 * Hash algorithm:
		 *
		 *   - `AuthenticatorInterface::ALGO_SHA1`
		 *   - `AuthenticatorInterface::ALGO_SHA256`
		 *   - `AuthenticatorInterface::ALGO_SHA512`
		 *
		 * @type string
		 */
		'algorithm'     => AuthenticatorInterface::ALGO_SHA1,

		/**
		 * Code length: either 6 or 8
		 *
		 * @type int
		 */
		'digits'        => 6,

		/**
		 * Validation period (seconds): 15 - 60
		 *
		 * @type int
		 */
		'period'        => 30,

		/**
		 * Length of the secret phrase (bytes, unencoded binary)
		 *
		 * @see \random_bytes()
		 *
		 * @type int
		 */
		'secret_length' => 20,

		/**
		 * number of allowed adjacent codes
		 *
		 * @type int
		 */
		'adjacent'      => 1,

		/**
		 * A fixed time offset that will be added to the current time value
		 *
		 * @see \chillerlan\Authenticator\Authenticators\AuthenticatorInterface::getCounter()
		 *
		 * @type int
		 */
		'time_offset'   => 0,
	];

	/** @var \chillerlan\Authenticator\Authenticators\AuthenticatorInterface */
	protected $authenticator;

	/** @var array */
	protected $options = [];

	/** @var string */
	protected $mode = AuthenticatorInterface::TOTP;

	/**
	 * Authenticator constructor
	 *
	 * @param array|null  $options
	 * @param string|null $secret
	 */
	public function __construct(array $options = null, $secret = null){

		if($options === null){
			$options = [];
		}

		$this->setOptions($options);

		if($secret !== null){
			$this->setSecret($secret);
		}

	}

	/**
	 * Sets an options instance and invokes an authenticator according to the given mode
	 *
	 * Please note that this will reset the secret phrase stored with the authenticator instance
	 * if a different mode than the current is given.
	 *
	 * @param array $options
	 *
	 * @return \chillerlan\Authenticator\Authenticator
	 * @throws \InvalidArgumentException
	 */
	public function setOptions(array $options){
		$defaults      = self::DEFAULTS;
		// replace settings with the current and given ones
		$this->options = array_replace($defaults, $this->options, $options);

		// remove unwanted keys
		foreach(array_keys($this->options) as $key){
			if(!isset($defaults[$key])){
				unset($this->options[$key]);
			}
		}

		// invoke a new authenticator interface if necessary
		if(!isset($this->authenticator) || $this->options['mode'] !== $this->mode){
			$mode  = strtolower($this->options['mode']);
			$modes = AuthenticatorInterface::MODES;

			if(!isset($modes[$mode])){
				throw new InvalidArgumentException('Invalid mode: '.$mode);
			}

			$class               = $modes[$mode];
			$this->mode          = $mode;
			$this->authenticator = new $class;
		}

		$this->authenticator->setOptions($this->options);

		return $this;
	}

	/**
	 * Sets a secret phrase from a Base32 representation
	 *
	 * @param string $encodedSecret
	 *
	 * @return \chillerlan\Authenticator\Authenticator
	 * @codeCoverageIgnore
	 */
	public function setSecret($encodedSecret){
		$this->authenticator->setSecret($encodedSecret);

		return $this;
	}

	/**
	 * Returns a Base32 representation of the current secret phrase
	 *
	 * @return string
	 * @codeCoverageIgnore
	 */
	public function getSecret(){
		return $this->authenticator->getSecret();
	}

	/**
	 * Generates a new (secure random) secret phrase
	 *
	 * @param int|null $length
	 *
	 * @return string
	 * @codeCoverageIgnore
	 */
	public function createSecret($length = null){
		return $this->authenticator->createSecret($length);
	}

	/**
	 * Creates a new OTP code with the given secret
	 *
	 * $data may be
	 *  - a UNIX timestamp (TOTP)
	 *  - a counter value (HOTP)
	 *
	 * @param int|null $data
	 *
	 * @return string
	 * @codeCoverageIgnore
	 */
	public function code($data = null){
		return $this->authenticator->code($data);
	}

	/**
	 * Checks the given $code against the secret
	 *
	 * $data may be
	 *  - a UNIX timestamp (TOTP)
	 *  - a counter value (HOTP)
	 *
	 * @param string   $otp
	 * @param int|null $data
	 *
	 * @return bool
	 * @codeCoverageIgnore
	 */
	public function verify($otp, $data = null){
		return $this->authenticator->verify($otp, $data);
	}

	/**
	 * Creates a URI for use in QR codes for example
	 *
	 * @link https://github.com/google/google-authenticator/wiki/Key-Uri-Format#parameters
	 *
	 * @param string    $label
	 * @param string    $issuer
	 * @param int|null  $hotpCounter
	 * @param bool|null $omitSettings
	 *
	 * @return string
	 * @throws \InvalidArgumentException
	 */
	public function getUri($label, $issuer, $hotpCounter = null, $omitSettings = null){

		if(!is_string($label)){
			throw new TypeError('$label is expected to be string'); // @codeCoverageIgnore
		}

		if(!is_string($issuer)){
			throw new TypeError('$issuer is expected to be string'); // @codeCoverageIgnore
		}

		$label  = trim($label);
		$issuer = trim($issuer);

		if(empty($label) || empty($issuer)){
			throw new InvalidArgumentException('$label and $issuer cannot be empty');
		}

		$values = [
			'secret' => $this->authenticator->getSecret(),
			'issuer' => $issuer,
		];

		if($omitSettings !== true){
			$values['digits']    = $this->options['digits'];
			$values['algorithm'] = $this->options['algorithm'];

			if($this->mode === AuthenticatorInterface::TOTP){
				$values['period'] = $this->options['period'];
			}

			if($this->mode === AuthenticatorInterface::HOTP && $hotpCounter !== null){
				$values['counter'] = $hotpCounter;
			}
		}

		$values = http_build_query($values, '', '&', PHP_QUERY_RFC3986);

		return sprintf('otpauth://%s/%s?%s', $this->mode, rawurlencode($label), $values);
	}

}
