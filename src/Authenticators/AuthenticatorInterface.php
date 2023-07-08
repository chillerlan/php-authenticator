<?php
/**
 * Interface AuthenticatorInterface
 *
 * @created      15.06.2023
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2023 smiley
 * @license      MIT
 */

namespace chillerlan\Authenticator\Authenticators;

/**
 *
 */
interface AuthenticatorInterface{

	const TOTP        = 'totp';
	const HOTP        = 'hotp';

	const ALGO_SHA1   = 'SHA1';
	const ALGO_SHA256 = 'SHA256';
	const ALGO_SHA512 = 'SHA512';

	const MODES = [
		self::HOTP => HOTP::class,
		self::TOTP => TOTP::class,
	];

	const HASH_ALGOS = [
		self::ALGO_SHA1,
		self::ALGO_SHA256,
		self::ALGO_SHA512,
	];

	/**
	 * Sets the options
	 *
	 * @param array $options
	 *
	 * @return \chillerlan\Authenticator\Authenticators\AuthenticatorInterface
	 */
	public function setOptions(array $options);

	/**
	 * Sets a secret phrase from an encoded representation
	 *
	 * @param string $encodedSecret
	 *
	 * @return \chillerlan\Authenticator\Authenticators\AuthenticatorInterface
	 * @throws \RuntimeException
	 */
	public function setSecret($encodedSecret);

	/**
	 * Returns an encoded representation of the current secret phrase
	 *
	 * @return string
	 * @throws \RuntimeException
	 */
	public function getSecret();

	/**
	 * Generates a new (secure random) secret phrase
	 *
	 * @param int|null $length
	 *
	 * @return string
	 * @throws \InvalidArgumentException
	 */
	public function createSecret($length = null);

	/**
	 * Prepares the given $data value and returns an integer that will be passed as counter value to the hash function
	 *
	 * @param int|null $data
	 *
	 * @return int
	 * @internal
	 */
	public function getCounter($data = null);

	/**
	 * HMAC hashes the given $data integer with the given secret
	 *
	 * @param int $counter
	 *
	 * @return string
	 * @throws \RuntimeException
	 * @internal
	 */
	public function getHMAC($counter);

	/**
	 * Extracts the intermediate code from the given $hmac hash
	 *
	 * @param string $hmac
	 *
	 * @return int
	 * @internal
	 */
	public function getCode($hmac);

	/**
	 * Formats the final output OTP from the given intermediate $code
	 *
	 * @param int $code
	 *
	 * @return string
	 * @internal
	 */
	public function getOTP($code);

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
	 */
	public function code($data = null);

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
	 */
	public function verify($otp, $data = null);

}
