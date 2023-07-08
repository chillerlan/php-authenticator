<?php
/**
 * Class TOTP
 *
 * @created      15.06.2023
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2023 smiley
 * @license      MIT
 */

namespace chillerlan\Authenticator\Authenticators;

use TypeError;
use function floor;
use function hash_equals;
use function is_int;
use function is_string;
use function time;

/**
 * @link https://tools.ietf.org/html/rfc6238
 */
class TOTP extends HOTP{

	/**
	 * @inheritDoc
	 */
	public function getCounter($data = null){

		if($data === null){
			$data = time();
		}

		if(!is_int($data)){
			throw new TypeError('$data is expected to be int'); // @codeCoverageIgnore
		}

		return (int)floor(($data + $this->time_offset) / $this->period);
	}

	/**
	 * @inheritDoc
	 */
	public function verify($otp, $data = null){

		if($this->adjacent === 0){
			return parent::verify($otp, $data); // @codeCoverageIgnore
		}

		if(!is_string($otp)){
			throw new TypeError('$code is expected to be string'); // @codeCoverageIgnore
		}

		$timeslice = $this->getCounter($data);
		// phpcs:ignore
		for($i = -$this->adjacent; $i <= $this->adjacent; $i++){
			$hash = $this->getHMAC($timeslice + $i);
			$code = $this->getOTP($this->getCode($hash));

			if(hash_equals($code, $otp)){
				return true;
			}
		}

		return false;
	}

}
