<?php
/**
 * Class Authenticator
 *
 * @created      24.11.2015
 * @author       Smiley <smiley@chillerlan.net>
 * @copyright    2015 Smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\Authenticator;

use chillerlan\Authenticator\Authenticators\AuthenticatorInterface;
use chillerlan\Settings\SettingsContainerInterface;
use SensitiveParameter;

/**
 * Yet another Google authenticator implementation!
 *
 * Note: This class has been reduced oover time to a front-end to the several authenticator classes
 *       (`HOTP`, `TOTP`, ...), which can be invoked on their own. `Authenticator` will remain for convenience.
 *
 * @link https://tools.ietf.org/html/rfc4226
 * @link https://tools.ietf.org/html/rfc6238
 * @link https://github.com/google/google-authenticator
 * @link https://openauthentication.org/specifications-technical-resources/
 * @link https://blog.ircmaxell.com/2014/11/its-all-about-time.html
 */
class Authenticator{

	protected SettingsContainerInterface|AuthenticatorOptions $options;
	protected AuthenticatorInterface                          $authenticator;

	/**
	 * Authenticator constructor
	 */
	public function __construct(
		SettingsContainerInterface|AuthenticatorOptions $options = new AuthenticatorOptions,
		#[SensitiveParameter] string|null $secret = null,
	){
		// phpcs:ignore
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
	 */
	public function setOptions(SettingsContainerInterface|AuthenticatorOptions $options):static{
		$this->options = $options;

		// invoke a new authenticator interface if necessary
		if(!isset($this->authenticator) || $this->authenticator::MODE !== $this->options->mode){
			$this->authenticator = new (AuthenticatorInterface::MODES[$this->options->mode])($this->options);
		}

		$this->authenticator->setOptions($this->options);

		return $this;
	}

	/**
	 * Sets a secret phrase from a Base32 representation
	 *
	 * @codeCoverageIgnore
	 */
	public function setSecret(#[SensitiveParameter] string $encodedSecret):static{
		$this->authenticator->setSecret($encodedSecret);

		return $this;
	}

	/**
	 * Returns a Base32 representation of the current secret phrase
	 *
	 * @codeCoverageIgnore
	 */
	public function getSecret():string{
		return $this->authenticator->getSecret();
	}

	/**
	 * Generates a new (secure random) secret phrase
	 *
	 * @codeCoverageIgnore
	 */
	public function createSecret(int|null $length = null):string{
		return $this->authenticator->createSecret($length);
	}

	/**
	 * Creates a new OTP code with the given secret
	 *
	 * $data may be
	 *  - a UNIX timestamp (TOTP)
	 *  - a counter value (HOTP)
	 *
	 * @codeCoverageIgnore
	 */
	public function code(int|null $data = null):string{
		return $this->authenticator->code($data);
	}

	/**
	 * Checks the given $code against the secret
	 *
	 * $data may be
	 *  - a UNIX timestamp (TOTP)
	 *  - a counter value (HOTP)
	 *
	 * @codeCoverageIgnore
	 */
	public function verify(#[SensitiveParameter] string $otp, int|null $data = null):bool{
		return $this->authenticator->verify($otp, $data);
	}

	/**
	 * Creates a URI for use in QR codes for example
	 *
	 * @link https://github.com/google/google-authenticator/wiki/Key-Uri-Format#parameters
	 *
	 * @deprecated 5.3.0 The parameter `$omitSettings` will be removed in favor of `AuthenticatorOptions::$omitUriSettings`
	 *                   in the next major version (6.x)
	 * @see \chillerlan\Authenticator\AuthenticatorOptionsTrait::$omitUriSettings
	 *
	 * @codeCoverageIgnore
	 */
	public function getUri(string $label, string $issuer, int|null $hotpCounter = null, bool|null $omitSettings = null):string{
		// a little reckless but good enough until the deprecated parameter is removed
		if($omitSettings !== null){
			$this->options->omitUriSettings = $omitSettings;
		}

		return $this->authenticator->getUri($label, $issuer, $hotpCounter);
	}

}
