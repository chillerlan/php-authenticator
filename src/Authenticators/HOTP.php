<?php
/**
 * Class HOTP
 *
 * @created      15.06.2023
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2023 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\Authenticator\Authenticators;

use RuntimeException;
use SensitiveParameter;
use function array_merge;
use function hash_equals;
use function hash_hmac;
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

	public const MODE = self::HOTP;

	public function getCounter(int|null $data = null):int{
		return ($data ?? 0);
	}

	public function getHMAC(int $counter):string{

		if($this->secret === null){
			throw new RuntimeException('No secret given');
		}
		// @codeCoverageIgnoreStart
		$data = (PHP_INT_SIZE < 8)
			// 32-bit
			? "\x00\x00\x00\x00".pack('N', $counter)
			// 64-bit
			: pack('J', $counter);
		// @codeCoverageIgnoreEnd
		return hash_hmac($this->options->algorithm, $data, $this->secret, true);
	}

	public function getCode(#[SensitiveParameter] string $hmac):int{
		$data = unpack('C*', $hmac);

		if($data === false){
			throw new RuntimeException('error while unpacking HMAC'); // @codeCoverageIgnore
		}

		$b = ($data[strlen($hmac)] & 0xF);

		return (($data[$b + 1] & 0x7F) << 24) | ($data[$b + 2] << 16) | ($data[$b + 3] << 8) | $data[$b + 4]; // phpcs:ignore
	}

	public function getOTP(#[SensitiveParameter] int $code):string{
		$code %= (10 ** $this->options->digits);

		return str_pad((string)$code, $this->options->digits, '0', STR_PAD_LEFT);
	}

	public function code(int|null $data = null):string{
		$hmac = $this->getHMAC($this->getCounter($data));

		return $this->getOTP($this->getCode($hmac));
	}

	public function verify(#[SensitiveParameter] string $otp, int|null $data = null):bool{
		return hash_equals($this->code($data), $otp);
	}

	protected function getUriParams(string $issuer, int|null $counter = null):array{

		$params = [
			'secret'  => $this->getSecret(),
			'issuer'  => $issuer,
			'counter' => $this->getCounter($counter),
		];

		if(!$this->options->omitUriSettings){
			$params = array_merge($params, [
				'digits'    => $this->options->digits,
				'algorithm' => $this->options->algorithm,
			]);
		}

		return $params;
	}

}
