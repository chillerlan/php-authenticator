<?php
/**
 * Trait AuthenticatorOptionsTrait
 *
 * @filesource   AuthenticatorOptionsTrait.php
 * @created      07.03.2019
 * @package      chillerlan\Authenticator
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2019 smiley
 * @license      MIT
 */

namespace chillerlan\Authenticator;

trait AuthenticatorOptionsTrait{

	/**
	 * Code length: either 6 or 8
	 *
	 * @var int
	 */
	protected $digits = 6;

	/**
	 * validation period (seconds): 15 - 60
	 *
	 * @var int
	 */
	protected $period = 30;

	/**
	 * length of the secret phrase (bytes, unencoded binary)
	 *
	 * @see \random_bytes()
	 *
	 * @var int
	 */
	protected $secret_length = 20;

	/**
	 * Hash algorithm: SHA1, SHA256 or SHA512
	 *
	 * @var string
	 */
	protected $algorithm = 'SHA1';

	/**
	 * Authenticator mode:
	 *
	 *   - totp = time based
	 *   - hotp = counter based
	 *
	 * @var string
	 */
	protected $mode = 'totp';

	/**
	 * number of allowed adjacent codes
	 *
	 * @var int
	 */
	protected $adjacent = 1;

	/**
	 * Sets the code length to either 6 or 8
	 *
	 * @param int $digits
	 *
	 * @return void
	 * @throws \chillerlan\Authenticator\AuthenticatorException
	 */
	protected function set_digits(int $digits):void{

		if(!in_array($digits, [6, 8], true)){
			throw new AuthenticatorException('Invalid code length: '.$digits);
		}

		$this->digits = $digits;
	}

	/**
	 * Sets the period to a value between 10 and 60 seconds
	 *
	 * @param int $period
	 *
	 * @return void
	 * @throws \chillerlan\Authenticator\AuthenticatorException
	 */
	protected function set_period(int $period):void{

		if($period < 15 || $period > 60){
			throw new AuthenticatorException('Invalid period: '.$period);
		}

		$this->period = $period;
	}

	/**
	 * @param string $algorithm
	 *
	 * @return void
	 * @throws \chillerlan\Authenticator\AuthenticatorException
	 */
	protected function set_algorithm(string $algorithm):void{
		$algorithm = strtoupper($algorithm);

		if(!in_array($algorithm, ['SHA1', 'SHA256', 'SHA512'], true)){
			throw new AuthenticatorException('Invalid algorithm: '.$algorithm);
		}

		$this->algorithm = $algorithm;
	}

	/**
	 * @param string $mode
	 *
	 * @return void
	 * @throws \chillerlan\Authenticator\AuthenticatorException
	 */
	protected function set_mode(string $mode):void{
		$mode = strtolower($mode);

		if(!in_array($mode, ['totp', 'hotp'], true)){
			throw new AuthenticatorException('Invalid mode: '.$mode);
		}

		$this->mode = $mode;
	}

	/**
	 * @param int $adjacent
	 *
	 * @return void
	 * @throws \chillerlan\Authenticator\AuthenticatorException
	 */
	protected function set_adjacent(int $adjacent):void{

		if($adjacent < 0){
			throw new AuthenticatorException('Invalid adjacent: '.$adjacent);
		}

		$this->adjacent = $adjacent;
	}

}
