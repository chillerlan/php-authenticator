<?php
/**
 * Trait AuthenticatorOptionsTrait
 *
 * @created      07.03.2019
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2019 smiley
 * @license      MIT
 *
 * @see https://github.com/phan/phan/issues/5491
 * @phan-file-suppress PhanUnreferencedUseNormal, PhanUnreferencedUseFunction, PhanPropertyHookWithDefaultValue
 */
declare(strict_types=1);

namespace chillerlan\Authenticator;

use chillerlan\Authenticator\Authenticators\AuthenticatorInterface;
use InvalidArgumentException;
use function in_array;
use function strtolower;
use function strtoupper;

trait AuthenticatorOptionsTrait{

	/**
	 * Code length: either 6 or 8
	 */
	public int $digits = 6 {
		set{

			if(!in_array($value, [6, 8], true)){
				throw new InvalidArgumentException('Invalid code length: '.$value);
			}

			$this->digits = $value;
		}
	}

	/**
	 * Validation period (seconds): 15 - 60
	 */
	public int $period = 30 {
		set{

			if($value < 15 || $value > 60){
				throw new InvalidArgumentException('Invalid period: '.$value);
			}

			$this->period = $value;
		}
	}

	/**
	 * Length of the secret phrase (bytes, unencoded binary)
	 *
	 * @see \random_bytes()
	 */
	public int $secret_length = 20 {
		set{

			if($value < 16 || $value > 1024){
				throw new InvalidArgumentException('Invalid secret length: '.$value);
			}

			$this->secret_length = $value;
		}
	}

	/**
	 * Hash algorithm:
	 *
	 *   - `AuthenticatorInterface::ALGO_SHA1`
	 *   - `AuthenticatorInterface::ALGO_SHA256`
	 *   - `AuthenticatorInterface::ALGO_SHA512`
	 */
	public string $algorithm = AuthenticatorInterface::ALGO_SHA1 {
		set{
			$value = strtoupper($value);

			if(!in_array($value, AuthenticatorInterface::HASH_ALGOS, true)){
				throw new InvalidArgumentException('Invalid algorithm: '.$value);
			}

			$this->algorithm = $value;
		}
	}

	/**
	 * Authenticator mode:
	 *
	 *   - `AuthenticatorInterface::HOTP`  = counter based
	 *   - `AuthenticatorInterface::TOTP`  = time based
	 *   - `AuthenticatorInterface::STEAM` = time based (Steam Guard)
	 */
	public string $mode = AuthenticatorInterface::TOTP {
		set{
			$value = strtolower($value);

			if(!isset(AuthenticatorInterface::MODES[$value])){
				throw new InvalidArgumentException('Invalid mode: '.$value);
			}

			$this->mode = $value;
		}
	}

	/**
	 * Number of allowed adjacent codes
	 */
	public int $adjacent = 1 {
		set{
			// limit to a sane amount
			if($value < 0 || $value > 20){
				throw new InvalidArgumentException('Invalid number of adjacent codes: '.$value);
			}

			$this->adjacent = $value;
		}
	}

	/**
	 * A fixed time offset that will be added to the current time value
	 *
	 * @see \chillerlan\Authenticator\Authenticators\AuthenticatorInterface::getCounter()
	 */
	public int $time_offset = 0;

	/**
	 * Whether to use local time or request server time from the API
	 *
	 * This can be useful when the device time sync is unreliable.
	 *
	 * note: API requests needs ext-curl installed
	 */
	public bool $useLocalTime = true;

	/**
	 * Whether to force refreshing server time on each call or use the time returned from the last request
	 */
	public bool $forceTimeRefresh = false;

	/**
	 * Whether to omit the additional settings in the URI for an authenticator app (algo, digits, period)
	 *
	 * @link https://github.com/google/google-authenticator/wiki/Key-Uri-Format#parameters
	 */
	public bool $omitUriSettings = true;

}
