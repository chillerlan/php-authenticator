<?php
/**
 * Class BattleNetTest
 *
 * @created      30.06.2023
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2023 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\AuthenticatorTest\Authenticators;

use chillerlan\Authenticator\AuthenticatorOptions;
use chillerlan\Authenticator\Authenticators\{AuthenticatorInterface, BattleNet};
use chillerlan\Authenticator\Common\Hex;
use Generator;
use function date;
use function dechex;
use function is_int;
use const PHP_INT_SIZE;

/**
 * @property \chillerlan\Authenticator\Authenticators\BattleNet $authenticatorInterface
 */
class BattleNetTest extends AuthenticatorInterfaceTestAbstract{

	protected const secret  = '3132333435363738393031323334353637383930';

	protected const BattleNetVectors = [
		// timestamps and time slices from RFC 6238, see https://tools.ietf.org/html/rfc6238#page-14
		[         59,        '1', '94287082'],
		[ 1111111109,  '23523ec', '07081804'],
		[ 1111111111,  '23523ed', '14050471'],
		[ 1234567890,  '273ef07', '89005924'],
		[ 2000000000,  '3f940aa', '69279037'],
		// 64bit only
		[20000000000, '27bc86aa', '65353130'],
	];

	protected function getInstance(AuthenticatorOptions $options):AuthenticatorInterface{
		return new BattleNet($options);
	}

	public function testSetGetSecret():void{
		$this->authenticatorInterface->setSecret($this::secret);

		$secret = $this->authenticatorInterface->getSecret();

		$this::assertSame($this::secret, $secret);
		$this::assertSame($this::rawsecret, Hex::decode($secret));
	}

	public function testCreateSecretDefaultLength():void{
		$this::markTestSkipped('N/A');
	}

	public function testCreateSecretWithLength():void{
		$this::markTestSkipped('N/A');
	}

	public function testCreateSecretCheckCharacterSet():void{
		$this::markTestSkipped('N/A');
	}

	public function testCreateSecretException():void{
		$this::markTestSkipped('N/A');
	}

	/**
	 * Timestamps and -slices from the RFC6238 page, codes from a verified implementation
	 *
	 * @see https://tools.ietf.org/html/rfc6238#page-14
	 */
	public static function battleNetVectors():Generator{
		foreach(self::BattleNetVectors as [$timestamp, $timeslice, $totp]){
			// skip 64bit numbers on 32bit PHP
			if(PHP_INT_SIZE < 8 && !is_int($timestamp)){
				continue;
			}

			yield date('Y-m-d H:i:s', $timestamp) => [$timestamp, $timeslice, $totp];
		}
	}

	/**
	 * @dataProvider battleNetVectors
	 */
	public function testIntermediateValues(int $timestamp, string $timeslice, string $totp):void{
		$this->authenticatorInterface->setSecret($this::secret);

		$timeslice_intermediate = $this->authenticatorInterface->getCounter($timestamp);

		$this::assertSame($timeslice, dechex($timeslice_intermediate));

		$hmac_intermediate      = $this->authenticatorInterface->getHMAC($timeslice_intermediate);
		$code_intermediate      = $this->authenticatorInterface->getCode($hmac_intermediate);
		$code_formatted         = $this->authenticatorInterface->getOTP($code_intermediate);

		$this::assertSame($totp, $code_formatted);
	}

	/**
	 * @dataProvider battleNetVectors
	 */
	public function testAdjacent(int $timestamp, string $timeslice, string $totp):void{
		$adjacent = 20;
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

}
