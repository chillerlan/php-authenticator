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
	 */
	public function setOptions(array $options):AuthenticatorInterface;

	/**
	 * Sets a secret phrase from an encoded representation
	 *
	 * @throws \RuntimeException
	 */
	public function setSecret(string $encodedSecret):AuthenticatorInterface;

	/**
	 * Returns an encoded representation of the current secret phrase
	 *
	 * @throws \RuntimeException
	 */
	public function getSecret():string;

	/**
	 * Generates a new (secure random) secret phrase
	 *
	 * @throws \InvalidArgumentException
	 */
	public function createSecret(int $length = null):string;

	/**
	 * Prepares the given $data value and returns an integer that will be passed as counter value to the hash function
	 *
	 * @internal
	 */
	public function getCounter(int $data = null):int;

	/**
	 * HMAC hashes the given $data integer with the given secret
	 *
	 * @internal
	 */
	public function getHMAC(int $counter):string;

	/**
	 * Extracts the intermediate code from the given $hmac hash
	 *
	 * @internal
	 */
	public function getCode(string $hmac):int;

	/**
	 * Formats the final output OTP from the given intermediate $code
	 *
	 * @internal
	 */
	public function getOTP(int $code):string;

	/**
	 * Creates a new OTP code with the given secret
	 *
	 * $data may be
	 *  - a UNIX timestamp (TOTP)
	 *  - a counter value (HOTP)
	 */
	public function code(int $data = null):string;

	/**
	 * Checks the given $code against the secret
	 *
	 * $data may be
	 *  - a UNIX timestamp (TOTP)
	 *  - a counter value (HOTP)
	 */
	public function verify(string $otp, int $data = null):bool;

}
