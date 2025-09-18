<?php
/**
 * Class TOTP
 *
 * @created      15.06.2023
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2023 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\Authenticator\Authenticators;

use SensitiveParameter;
use function array_merge;
use function floor;
use function hash_equals;
use function time;

/**
 * @link https://tools.ietf.org/html/rfc6238
 */
class TOTP extends HOTP{

	public const MODE = self::TOTP;

	public function getCounter(int|null $data = null):int{
		$data ??= time();

		if($this->options->useLocalTime === false){
			$data = $this->getServerTime();
		}

		return (int)floor(($data + $this->options->time_offset) / $this->options->period);
	}

	public function verify(#[SensitiveParameter] string $otp, int|null $data = null):bool{
		$limit = $this->options->adjacent;

		if($limit === 0){
			return parent::verify($otp, $data); // @codeCoverageIgnore
		}

		$timeslice = $this->getCounter($data);
		// phpcs:ignore
		for($i = -$limit; $i <= $limit; $i++){
			$hash = $this->getHMAC($timeslice + $i);
			$code = $this->getOTP($this->getCode($hash));

			if(hash_equals($code, $otp)){
				return true;
			}
		}

		return false;
	}

	protected function getUriParams(string $issuer, int|null $counter = null):array{

		$params = [
			'secret'  => $this->getSecret(),
			'issuer'  => $issuer,
		];

		if(!$this->options->omitUriSettings){
			$params = array_merge($params, [
				'digits'    => $this->options->digits,
				'algorithm' => $this->options->algorithm,
				'period'    => $this->options->period,
			]);
		}

		return $params;
	}

}
