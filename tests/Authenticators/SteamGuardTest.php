<?php
/**
 * Class SteamGuardTest
 *
 * @created      20.06.2023
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2023 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\AuthenticatorTest\Authenticators;

use chillerlan\Authenticator\AuthenticatorOptions;
use chillerlan\Authenticator\Authenticators\{AuthenticatorInterface, SteamGuard};
use chillerlan\Authenticator\Common\Base64;
use PHPUnit\Framework\Attributes\{DataProvider, Test};
use Generator;
use function date, dechex, is_int, strlen;
use const PHP_INT_SIZE;

/**
 * @property \chillerlan\Authenticator\Authenticators\SteamGuard $authenticatorInterface
 */
class SteamGuardTest extends AuthenticatorInterfaceTestAbstract{

	protected const secret  = 'MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=';

	protected const SteamGuardVectors = [
		// timestamps and time slices from RFC 6238, see https://tools.ietf.org/html/rfc6238#page-14
		[         59,        '1', 'PV9M4'],
		[ 1111111109,  '23523ec', 'PY4YB'],
		[ 1111111111,  '23523ed', '5PP3V'],
		[ 1234567890,  '273ef07', 'VHHQY'],
		[ 2000000000,  '3f940aa', '9N776'],
		// 64bit only
		[20000000000, '27bc86aa', 'R5DMB'],
	];

	protected function getInstance(AuthenticatorOptions $options):AuthenticatorInterface{
		return new SteamGuard($options);
	}

	#[Test]
	public function setGetSecret():void{
		$this->authenticatorInterface->setSecret($this::secret);

		$secret = $this->authenticatorInterface->getSecret();

		$this::assertSame($this::secret, $secret);
		$this::assertSame($this::rawsecret, Base64::decode($secret));
	}

	#[Test]
	public function createSecretDefaultLength():void{
		$this::assertSame(
			$this->options->secret_length,
			strlen(Base64::decode($this->authenticatorInterface->createSecret())),
		);
	}

	#[Test]
	public function createSecretWithLength():void{

		for($secretLength = 16; $secretLength <= 512; $secretLength += 8){
			$secret = Base64::decode($this->authenticatorInterface->createSecret($secretLength));

			$this::assertSame($secretLength, strlen($secret));
		}

	}

	#[Test]
	public function createSecretCheckCharacterSet():void{
		$secret = $this->authenticatorInterface->createSecret(32);

		$this::assertMatchesRegularExpression('#^['.Base64::CHARSET.']+$#', $secret);
	}

	/**
	 * Timestamps and -slices from the RFC6238 page, codes from a verified implementation
	 *
	 * @see https://tools.ietf.org/html/rfc6238#page-14
	 */
	public static function steamGuardVectors():Generator{
		foreach(self::SteamGuardVectors as [$timestamp, $timeslice, $totp]){
			// skip 64bit numbers on 32bit PHP
			if(PHP_INT_SIZE < 8 && !is_int($timestamp)){
				continue;
			}

			yield date('Y-m-d H:i:s', $timestamp) => [$timestamp, $timeslice, $totp];
		}
	}

	#[DataProvider('steamGuardVectors')]
	public function testIntermediateValues(int $timestamp, string $timeslice, string $totp):void{
		$this->authenticatorInterface->setSecret($this::secret);

		$timeslice_intermediate = $this->authenticatorInterface->getCounter($timestamp);

		$this::assertSame($timeslice, dechex($timeslice_intermediate));

		$hmac_intermediate      = $this->authenticatorInterface->getHMAC($timeslice_intermediate);
		$code_intermediate      = $this->authenticatorInterface->getCode($hmac_intermediate);
		$code_formatted         = $this->authenticatorInterface->getOTP($code_intermediate);

		$this::assertSame($totp, $code_formatted);
	}

	#[DataProvider('steamGuardVectors')]
	public function testAdjacent(int $timestamp, string $timeslice, string $totp):void{
		$adjacent = 10;
		$limit    = (2 * $adjacent);

		$this->authenticatorInterface->setSecret($this::secret);

		$this->options->adjacent = $adjacent;
		// phpcs:ignore
		for($i = -$limit; $i <= $limit; $i++){
			$this->options->time_offset = ($i * $this->options->period);

			$verify = $this->authenticatorInterface->verify($totp, $timestamp);

			($i < -$adjacent || $i > $adjacent)
				? $this::assertFalse($verify)
				: $this::assertTrue($verify);
		}

	}

	public static function uriSettingsProvider():array{
		return [
			[[], ''],
		];
	}

	/**
	 * @param array<string, mixed> $options
	 */
	#[Test]
	#[DataProvider('uriSettingsProvider')]
	public function getUri(array $options, string $expected):void{
		$this::markTestSkipped('N/A');
	}

}
