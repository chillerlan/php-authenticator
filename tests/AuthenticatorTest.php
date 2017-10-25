<?php
/**
 *
 * @filesource   AuthenticatorTest.php
 * @created      06.12.2015
 * @author       Smiley <smiley@chillerlan.net>
 * @copyright    2015 Smiley
 * @license      MIT
 */

namespace chillerlan\GoogleAuthTest;

use chillerlan\GoogleAuth\{Authenticator, Base32};
use PHPUnit\Framework\TestCase;

class AuthenticatorTest extends TestCase{

	protected $secret;
	protected $falseSecret = 'SECRETTEST234567';
	protected $invalidSecret = 'This-is-an-invalid-secret-phrase!';
	protected $label = 'test';
	protected $issuer = 'chillerlan.net';

	/**
	 * @var \chillerlan\GoogleAuth\Authenticator
	 */
	protected $authenticator;

	protected function setUp(){
		$this->authenticator = new Authenticator(30, 6);

		$this->secret = $this->authenticator->createSecret(16);
	}

	public function testSetDigits(){
		foreach([6, 8] as $digits){
			$this->authenticator->digits = $digits;
			$this->assertEquals($digits, $this->authenticator->digits);
		}
	}

	/**
	 * @expectedException \chillerlan\GoogleAuth\AuthenticatorException
	 */
	public function testSetDigitsException(){
		$this->authenticator->digits = 7;
	}

	public function testSetPeriod(){
		for($period = 15; $period <= 60; $period++){
			$this->authenticator->period = $period;
			$this->assertEquals($period, $this->authenticator->period);
		}
	}

	/**
	 * @expectedException \chillerlan\GoogleAuth\AuthenticatorException
	 */
	public function testSetPeriodException(){
		$this->authenticator->period = 1;
	}

	public function testCreateSecretDefaultLength(){
		$this->assertEquals(16, strlen($this->authenticator->createSecret()));
	}

	public function testCreateSecretWithLength(){
		for($secretLength = 16; $secretLength <= 128; $secretLength++){
			$this->assertEquals($secretLength, strlen($this->authenticator->createSecret($secretLength)));
		}
	}

	public function testCreateSecretCheckCharacterSet(){
		$this->assertRegExp('/^['.Base32::RFC3548.']+$/', $this->secret);
	}

	/**
	 * @expectedException \chillerlan\GoogleAuth\AuthenticatorException
	 */
	public function testCreateSecretException(){
		$this->authenticator->createSecret(10);
	}


	public function codeProvider(){
		// secret, time, code
		return [
			[$this->falseSecret,          0, '730741'],
			[$this->falseSecret, 1385909245, '040137'],
			[$this->falseSecret, 1378934578, '341779'],
			[$this->falseSecret, 1449438863, '889844'],
		];
	}

	/**
	 * @dataProvider codeProvider
	 */
	public function testGetCode($secret, $timestamp, $code){
		$this->assertEquals($code, $this->authenticator->getCode($secret, floor($timestamp / $this->authenticator->period)));
	}

	/**
	 * @expectedException \chillerlan\GoogleAuth\AuthenticatorException
	 */
	public function testGetCodeException(){
		$this->authenticator->getCode($this->invalidSecret);
	}

	public function testVerifyCode(){
		$this->assertEquals(true, $this->authenticator->verifyCode($this->authenticator->getCode($this->secret), $this->secret));
		$this->assertEquals(false, $this->authenticator->verifyCode($this->authenticator->getCode($this->secret), $this->falseSecret));
		$this->assertEquals(false, $this->authenticator->verifyCode('123456', $this->secret));
	}

	public function testVerifyCodeWithTimeslice(){
		$code = $this->authenticator->getCode($this->secret);
		$timestamp = time();
		$p = $this->authenticator->period;

		// first adjacent code (default value)
		$timeslice = floor(($timestamp - (1 * $p)) / $p);
		$this->assertEquals(true, $this->authenticator->verifyCode($code, $this->secret, $timeslice));

		$timeslice = floor(($timestamp - (2 * $p)) / $p);
		$this->assertEquals(false, $this->authenticator->verifyCode($code, $this->secret, $timeslice));
	}

	public function testVerifyCodeWithTimesliceAndAdjacent(){
		$code = $this->authenticator->getCode($this->secret);
		$timestamp = time();
		$adjacent = 100;
		$p = $this->authenticator->period;

		for($i = 0; $i <= $adjacent + 1; $i++){
			$timeslice = floor(($timestamp - ($i * $p)) / $p);
			$verify = $this->authenticator->verifyCode($code, $this->secret, $timeslice, $adjacent);

			$this->assertEquals($i <= $adjacent, $verify);
		}

	}

	// https://github.com/PHPGangsta/GoogleAuthenticator/pull/25
	public function testVerifyCodeWithLeadingZero(){
		$code = $this->authenticator->getCode($this->secret);
		$this->assertEquals(true, $this->authenticator->verifyCode($code, $this->secret));

		$code = '0'.$code;
		$this->assertEquals(false, $this->authenticator->verifyCode($code, $this->secret));
	}

	/**
	 * @expectedException \chillerlan\GoogleAuth\AuthenticatorException
	 */
	public function testVerifyCodeException(){
		$this->authenticator->verifyCode($this->invalidSecret, $this->authenticator->getCode($this->secret));
	}


	public function testGetUri(){
		$values = [
			'secret' => $this->secret,
			'issuer' => $this->issuer,
		];

		$expected = 'otpauth://totp/'.$this->label.'?';
		$this->assertEquals($expected.http_build_query($values), $this->authenticator->getUri($this->secret, $this->label, $this->issuer));

		$this->authenticator->digits = 8;
		$values['digits'] = $this->authenticator->digits;
		$this->assertEquals($expected.http_build_query($values), $this->authenticator->getUri($this->secret, $this->label, $this->issuer));

		$this->authenticator->period = 45;
		$values['period'] = $this->authenticator->period;
		$this->assertEquals($expected.http_build_query($values), $this->authenticator->getUri($this->secret, $this->label, $this->issuer));

	}

	/**
	 * @expectedException \chillerlan\GoogleAuth\AuthenticatorException
	 */
	public function testGetUriException(){
		$this->authenticator->getUri($this->invalidSecret, $this->label, $this->issuer);
	}

}
