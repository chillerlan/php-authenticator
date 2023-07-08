<?php
/**
 * Class TOTPTest
 *
 * @created      19.06.2023
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2023 smiley
 * @license      MIT
 */

namespace chillerlan\AuthenticatorTest\Authenticators;

use chillerlan\Authenticator\Authenticators\TOTP;
use function date;
use function dechex;
use function is_int;
use function sprintf;
use const PHP_INT_SIZE;

/**
 *
 */
class TOTPTest extends AuthenticatorInterfaceTestAbstract{

	/**
	 * @see https://tools.ietf.org/html/rfc6238#page-14
	 */
	const rfc6238Vectors = [
		['sha1'  ,          59,        '1', 1094287082, '94287082'],
		['sha256',          59,        '1',  746119246, '46119246'],
		['sha512',          59,        '1',  490693936, '90693936'],

		['sha1'  ,  1111111109,  '23523ec',  907081804, '07081804'],
		['sha256',  1111111109,  '23523ec', 1568084774, '68084774'],
		['sha512',  1111111109,  '23523ec',  225091201, '25091201'],

		['sha1'  ,  1111111111,  '23523ed',  414050471, '14050471'],
		['sha256',  1111111111,  '23523ed', 1167062674, '67062674'],
		['sha512',  1111111111,  '23523ed', 1899943326, '99943326'],

		['sha1'  ,  1234567890,  '273ef07',  689005924, '89005924'],
		['sha256',  1234567890,  '273ef07',   91819424, '91819424'],
		['sha512',  1234567890,  '273ef07', 1493441116, '93441116'],

		['sha1'  ,  2000000000,  '3f940aa', 2069279037, '69279037'],
		['sha256',  2000000000,  '3f940aa', 1790698825, '90698825'],
		['sha512',  2000000000,  '3f940aa', 1938618901, '38618901'],
		// 64bit only
		['sha1'  , 20000000000, '27bc86aa', 1465353130, '65353130'],
		['sha256', 20000000000, '27bc86aa',  777737706, '77737706'],
		['sha512', 20000000000, '27bc86aa', 1047863826, '47863826'],
	];

	const secrets = [
		'sha1'   => self::secret,
		'sha256' => 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA',
		'sha512' => 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA',
	];

	protected function getInstance(){
		return new TOTP;
	}

	public static function totpVectors(){
		foreach(self::rfc6238Vectors as list($algorithm, $timestamp, $timeslice, $code, $totp)){
			// skip 64bit numbers on 32bit PHP
			if(PHP_INT_SIZE < 8 && !is_int($timestamp)){
				continue;
			}

			$key = sprintf('%s %s',date('Y-m-d H:i:s', $timestamp), $algorithm);

			yield $key => [$algorithm, $timestamp, $timeslice, $code, $totp];
		}
	}

	/**
	 * @param string $algorithm
	 * @param int    $timestamp
	 * @param string $timeslice
	 * @param int    $code
	 * @param string $totp
	 *
	 * @return void
	 *
	 * @dataProvider totpVectors
	 */
	public function testIntermediateValues($algorithm, $timestamp, $timeslice, $code, $totp){

		$options = [
			'digits'    => 8,
			'algorithm' => $algorithm,
			'adjacent'  => 0,
		];

		$this->authenticatorInterface
			->setOptions($options)
			->setSecret(self::secrets[$algorithm])
		;

		$timeslice_intermediate = $this->authenticatorInterface->getCounter($timestamp);
		$hmac_intermediate      = $this->authenticatorInterface->getHMAC($timeslice_intermediate);
		$code_intermediate      = $this->authenticatorInterface->getCode($hmac_intermediate);
		$code_formatted         = $this->authenticatorInterface->getOTP($code_intermediate);

		$this::assertSame($timeslice, dechex($timeslice_intermediate));
		$this::assertSame($code, $code_intermediate);
		$this::assertSame($totp, $code_formatted);
		// coverage
		$this::assertTrue($this->authenticatorInterface->verify($totp, $timestamp));
	}

	/**
	 * @param string $algorithm
	 * @param int    $timestamp
	 * @param string $timeslice
	 * @param int    $code
	 * @param string $totp
	 *
	 * @return void
	 *
	 * @dataProvider totpVectors
	 */
	public function testAdjacent($algorithm, $timestamp, $timeslice, $code, $totp){
		$adjacent = 20;
		$limit    = (2 * $adjacent);

		$options = [
			'digits'    => 8,
			'period'    => 30, // (default) the codes were generated with a 30-second period
			'algorithm' => $algorithm,
			'adjacent'  => $adjacent,
		];

		$this->authenticatorInterface
			->setOptions($options)
			->setSecret(self::secrets[$algorithm])
		;
		// phpcs:ignore
		for($i = -$limit; $i <= $limit; $i++){
			$this->authenticatorInterface->setOptions(['time_offset' => ($i * $options['period'])]);

			$verify = $this->authenticatorInterface->verify($totp, $timestamp);

			($i < -$adjacent || $i > $adjacent)
				? $this::assertFalse($verify)
				: $this::assertTrue($verify);
		}

	}

}
