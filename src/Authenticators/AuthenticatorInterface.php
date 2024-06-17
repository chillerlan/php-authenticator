<?php
/**
 * Interface AuthenticatorInterface
 *
 * @created      15.06.2023
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2023 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\Authenticator\Authenticators;

use chillerlan\Settings\SettingsContainerInterface;
use SensitiveParameter;

/**
 *
 */
interface AuthenticatorInterface{

	public const TOTP        = 'totp';
	public const HOTP        = 'hotp';
	public const STEAM_GUARD = 'steam';

	public const ALGO_SHA1   = 'SHA1';
	public const ALGO_SHA256 = 'SHA256';
	public const ALGO_SHA512 = 'SHA512';

	public const MODES = [
		self::HOTP        => HOTP::class,
		self::TOTP        => TOTP::class,
		self::STEAM_GUARD => SteamGuard::class,
	];

	public const HASH_ALGOS = [
		self::ALGO_SHA1,
		self::ALGO_SHA256,
		self::ALGO_SHA512,
	];

	/**
	 * Sets the options
	 */
	public function setOptions(SettingsContainerInterface $options):AuthenticatorInterface;

	/**
	 * Sets a secret phrase from an encoded representation
	 *
	 * @throws \RuntimeException
	 */
	public function setSecret(#[SensitiveParameter] string $encodedSecret):AuthenticatorInterface;

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
	 * Returns the current server time as UNIX timestamp for the given application (or `time()` if not applicable)
	 */
	public function getServertime():int;

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
	public function getCode(#[SensitiveParameter] string $hmac):int;

	/**
	 * Formats the final output OTP from the given intermediate $code
	 *
	 * @internal
	 */
	public function getOTP(#[SensitiveParameter] int $code):string;

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
	public function verify(#[SensitiveParameter] string $otp, int $data = null):bool;

}
