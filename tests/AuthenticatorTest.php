<?php
/**
 *
 * @filesource   AuthenticatorTest.php
 * @created      06.12.2015
 * @author       Smiley <smiley@chillerlan.net>
 * @copyright    2015 Smiley
 * @license      MIT
 */

namespace chillerlan\AuthenticatorTest;

use chillerlan\Authenticator\{Authenticator, Base32};
use PHPUnit\Framework\TestCase;

class AuthenticatorTest extends TestCase{

	protected $secret;
	protected $falseSecret = 'SECRETTEST234567';
	protected $invalidSecret = 'This-is-an-invalid-secret-phrase!';
	protected $label = 'some test-label';
	protected $issuer = 'chillerlan.net';

	/**
	 * @var \chillerlan\Authenticator\Authenticator
	 */
	protected $authenticator;

	protected function setUp(){
		$this->authenticator = new Authenticator;

		$this->secret = $this->authenticator->createSecret(16);
	}

	public function testSetDigits(){
		foreach([6, 8] as $digits){
			$this->authenticator->setDigits($digits);
			$this->assertSame($digits, $this->authenticator->getDigits());
		}
	}

	/**
	 * @expectedException \chillerlan\Authenticator\AuthenticatorException
	 * @expectedExceptionMessage Invalid code length
	 */
	public function testSetDigitsException(){
		$this->authenticator->setDigits(9);
	}

	public function testSetPeriod(){
		for($period = 15; $period <= 60; $period++){
			$this->authenticator->setPeriod($period);
			$this->assertSame($period, $this->authenticator->getPeriod());
		}
	}

	/**
	 * @expectedException \chillerlan\Authenticator\AuthenticatorException
	 * @expectedExceptionMessage Invalid period
	 */
	public function testSetPeriodException(){
		$this->authenticator->setPeriod(1);
	}

	public function testSetAlgorithm(){
		foreach(['sha1', 'sha256', 'sha512'] as $algo){
			$this->authenticator->setAlgorithm($algo);
			$this->assertSame(strtoupper($algo), $this->authenticator->getAlgorithm());
		}
	}

	/**
	 * @expectedException \chillerlan\Authenticator\AuthenticatorException
	 * @expectedExceptionMessage Invalid algorithm
	 */
	public function testSetAlgorithmException(){
		$this->authenticator->setAlgorithm('florps');
	}

	public function testSetMode(){
		foreach(['totp', 'hotp'] as $mode){
			$this->authenticator->setMode($mode);
			$this->assertSame($mode, $this->authenticator->getMode());
		}
	}

	/**
	 * @expectedException \chillerlan\Authenticator\AuthenticatorException
	 * @expectedExceptionMessage Invalid algorithm
	 */
	public function testSetModeException(){
		$this->authenticator->setMode('florps');
	}

	public function testCreateSecretDefaultLength(){
		$this->assertSame(
			$this->authenticator::DEFAULT_SECRET_LENGTH,
			strlen((new Base32)->toString($this->authenticator->createSecret()))
		);
	}

	public function testCreateSecretWithLength(){
		for($secretLength = 16; $secretLength <= 128; $secretLength++){
			$this->assertSame($secretLength, strlen((new Base32)->toString($this->authenticator->createSecret($secretLength))));
		}
	}

	public function testCreateSecretCheckCharacterSet(){
		$this->assertRegExp('/^['.Base32::RFC3548.']+$/', $this->secret);
	}

	/**
	 * @expectedException \chillerlan\Authenticator\AuthenticatorException
	 * @expectedExceptionMessage Invalid secret length
	 */
	public function testCreateSecretException(){
		$this->authenticator->createSecret(10);
	}

	public function totpCodeProvider(){
		// time, code (unverified values)
		return [
			[         0, '730741'],
			[1385909245, '040137'],
			[1378934578, '341779'],
			[1449438863, '889844'],
		];
	}

	/**
	 * coverage
	 *
	 * @dataProvider totpCodeProvider
	 */
	public function testGetCodeTOTP($timestamp, $code){
		$this->assertTrue($this->authenticator->setSecret($this->falseSecret)->verify($code, $timestamp));
	}

	public function hotpCodeProvider(){
		// counter, code (unverified values)
		return [
			[  0, '730741'],
			[  1, '219808'],
			[ 42, '803961'],
			[253, '403837'],
			[254, '442560'],
			[255, '606507'],
			[256, '918691'],
		];
	}

	/**
	 * coverage
	 *
	 * @dataProvider hotpCodeProvider
	 */
	public function testGetCodeHOTP($counter, $code){
		$this->assertTrue($this->authenticator->setMode('hotp')->setSecret($this->falseSecret)->verify($code, $counter));
		$this->assertSame($counter + 1, $this->authenticator->getCounter());
	}

	/**
	 * @expectedException \chillerlan\Authenticator\AuthenticatorException
	 * @expectedExceptionMessage Invalid secret phrase
	 */
	public function testGetCodeException(){
		$this->authenticator
			->setSecret($this->invalidSecret)
			->code();
	}

	public function testVerifyCode(){
		$this->assertTrue($this->authenticator->verify($this->authenticator->code()));
		$this->assertFalse($this->authenticator->verify('123456'));

		$a2 = clone $this->authenticator;
		$a2->setSecret($this->falseSecret);

		$this->assertFalse($this->authenticator->verify($a2->code()));
	}

	public function testVerifyCodeWithTimeslice(){
		$code = $this->authenticator->code();
		$timestamp = time();
		$p = $this->authenticator->getPeriod();

		// first adjacent code (default value)
		$this->assertTrue($this->authenticator->verify($code, $timestamp - 1 * $p));
		$this->assertFalse($this->authenticator->verify($code, $timestamp - 2 * $p));
	}

	public function testVerifyCodeWithTimesliceAndAdjacent(){
		$code = $this->authenticator->code();
		$timestamp = time();
		$adjacent = 100;
		$p = $this->authenticator->getPeriod();

		for($i = 0; $i <= $adjacent + 1; $i++){
			$verify = $this->authenticator->verify($code, $timestamp - $i * $p, $adjacent);

			$i <= $adjacent
				? $this->assertTrue($verify)
				: $this->assertFalse($verify);
		}

	}

	// https://github.com/PHPGangsta/GoogleAuthenticator/pull/25
	public function testVerifyCodeWithLeadingZero(){
		$code = $this->authenticator->code();
		$this->assertTrue($this->authenticator->verify($code));
		$this->assertFalse($this->authenticator->verify('0'.$code));
	}

	public function testGetUri(){
		$expected = '/'.rawurlencode($this->label).'?secret='.$this->secret.'&issuer='.$this->issuer;

		$this->assertSame('otpauth://'.$this->authenticator->getMode().$expected.'&digits=6&period=30&algorithm=SHA1', $this->authenticator->getUri($this->label, $this->issuer));

		$this->authenticator->setDigits(8);
		$this->assertSame('otpauth://'.$this->authenticator->getMode().$expected.'&digits=8&period=30&algorithm=SHA1', $this->authenticator->getUri($this->label, $this->issuer));

		$this->authenticator->setPeriod(45);
		$this->assertSame('otpauth://'.$this->authenticator->getMode().$expected.'&digits=8&period=45&algorithm=SHA1', $this->authenticator->getUri($this->label, $this->issuer));

		$this->authenticator->setMode('hotp');
		$this->assertSame('otpauth://'.$this->authenticator->getMode().$expected.'&digits=8&algorithm=SHA1', $this->authenticator->getUri($this->label, $this->issuer));

		$this->authenticator->setAlgorithm('SHA512');
		$this->assertSame('otpauth://'.$this->authenticator->getMode().$expected.'&digits=8&algorithm=SHA512', $this->authenticator->getUri($this->label, $this->issuer));
	}

	public function hotpVectors(){
		return [
			// https://tools.ietf.org/html/rfc4226#page-32
			[0, '755224'],
			[1, '287082'],
			[2, '359152'],
			[3, '969429'],
			[4, '338314'],
			[5, '254676'],
			[6, '287922'],
			[7, '162583'],
			[8, '399871'],
			[9, '520489'],
		];
	}

	/**
	 * @dataProvider hotpVectors
	 * @link https://github.com/winauth/winauth/issues/449#issuecomment-353670105
	 *
	 * @param int    $counter
	 * @param string $code
	 */
	public function testHOTP(int $counter, string $code){
		$this->authenticator
			->setSecret((new Base32)->fromString('12345678901234567890')) // -> GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
			->setMode('hotp');

		$this->assertFalse($this->authenticator->verify($code, $counter - 2));
		$this->assertTrue($this->authenticator->verify($code, $counter - 1));
		$this->assertTrue($this->authenticator->verify($code, $counter));
		$this->assertTrue($this->authenticator->verify($code, $counter + 1));
		$this->assertFalse($this->authenticator->verify($code, $counter + 2));
	}

	public function totpVectors(){
		return [
			// https://tools.ietf.org/html/rfc6238#page-14
			[         59, '94287082', 'sha1'  ],
			[ 1111111109, '07081804', 'sha1'  ],
			[ 1111111111, '14050471', 'sha1'  ],
			[ 1234567890, '89005924', 'sha1'  ],
			[ 2000000000, '69279037', 'sha1'  ],
			[20000000000, '65353130', 'sha1'  ],
			[         59, '46119246', 'sha256'],
			[ 1111111109, '68084774', 'sha256'],
			[ 1111111111, '67062674', 'sha256'],
			[ 1234567890, '91819424', 'sha256'],
			[ 2000000000, '90698825', 'sha256'],
			[20000000000, '77737706', 'sha256'],
			[         59, '90693936', 'sha512'],
			[ 1111111109, '25091201', 'sha512'],
			[ 1111111111, '99943326', 'sha512'],
			[ 1234567890, '93441116', 'sha512'],
			[ 2000000000, '38618901', 'sha512'],
			[20000000000, '47863826', 'sha512'],
		];
	}


	/**
	 * @dataProvider totpVectors
	 *
	 * @param int    $timestamp
	 * @param string $code
	 * @param string $algorithm
	 */
	public function testTOTP(int $timestamp, string $code, string $algorithm){
		$s = '12345678901234567890';

		$secret = [
			'sha1'   => $s,
			'sha256' => str_pad($s, 32, $s, STR_PAD_RIGHT),
			'sha512' => str_pad($s, 64, $s, STR_PAD_RIGHT),
		][$algorithm];

		$this->authenticator
			->setSecret((new Base32)->fromString($secret))
			->setDigits(8)
			->setAlgorithm($algorithm)
		;

		$this->assertFalse($this->authenticator->verify($code, $timestamp - 60));
		$this->assertTrue($this->authenticator->verify($code, $timestamp - 30));
		$this->assertTrue($this->authenticator->verify($code, $timestamp));
		$this->assertTrue($this->authenticator->verify($code, $timestamp + 30));
		$this->assertFalse($this->authenticator->verify($code, $timestamp + 60));
	}

}
