<?php
/**
 * Class HOTP
 *
 * @created      15.06.2023
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2023 smiley
 * @license      MIT
 */

namespace chillerlan\Authenticator\Authenticators;

use RuntimeException;
use TypeError;
use function hash_equals;
use function hash_hmac;
use function is_int;
use function is_string;
use function pack;
use function str_pad;
use function strlen;
use function unpack;
use const PHP_INT_SIZE;
use const STR_PAD_LEFT;

/**
 * @link https://tools.ietf.org/html/rfc4226
 */
class HOTP extends AuthenticatorAbstract{

	/**
	 * @inheritDoc
	 */
	public function getCounter($data = null){

		if($data === null){
			$data = 0;
		}

		if(!is_int($data)){
			throw new TypeError('$data is expected to be int'); // @codeCoverageIgnore
		}

		return ($data);
	}

	/**
	 * @inheritDoc
	 */
	public function getHMAC($counter){

		if($this->secret === null){
			throw new RuntimeException('No secret given');
		}
		// @codeCoverageIgnoreStart
		$data = (PHP_INT_SIZE < 8)
			? "\x00\x00\x00\x00".pack('N', $counter)
			: pack('J', $counter);
		// @codeCoverageIgnoreEnd
		return hash_hmac($this->algorithm, $data, $this->secret, true);
	}

	/**
	 * @inheritDoc
	 */
	public function getCode($hmac){
		$data = unpack('C*', $hmac);
		$b    = ($data[strlen($hmac)] & 0xF);
		// phpcs:ignore
		return (($data[$b + 1] & 0x7F) << 24) | ($data[$b + 2] << 16) | ($data[$b + 3] << 8) | $data[$b + 4];
	}

	/**
	 * @inheritDoc
	 */
	public function getOTP($code){
		$code %= (10 ** $this->digits);

		return str_pad((string)$code, $this->digits, '0', STR_PAD_LEFT);
	}

	/**
	 * @inheritDoc
	 */
	public function code($data = null){
		$hmac = $this->getHMAC($this->getCounter($data));

		return $this->getOTP($this->getCode($hmac));
	}

	/**
	 * @inheritDoc
	 */
	public function verify($otp, $data = null){

		if(!is_string($otp)){
			throw new TypeError('$code is expected to be string'); // @codeCoverageIgnore
		}

		return hash_equals($this->code($data), $otp);
	}

}
