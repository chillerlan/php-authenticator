<?php
/**
 *
 * @filesource   AuthenticatorTest.php
 * @created      06.12.2015
 * @author       Smiley <smiley@chillerlan.net>
 * @copyright    2015 Smiley
 * @license      MIT
 */

use chillerlan\GoogleAuth\Authenticator;
use chillerlan\Base32\Base32;

class AuthenticatorTest extends PHPUnit_Framework_TestCase{

	protected $secret;
	protected $falseSecret = 'SECRETTEST234567';
	protected $invalidSecret = 'This-is-an-invalid-secret-phrase!';
	protected $label = 'test';
	protected $issuer = 'chillerlan.net';

	protected function setUp(){
		$this->secret = Authenticator::createSecret();
	}

	protected function tearDown(){
		Authenticator::setDigits();
		Authenticator::setPeriod();
	}

	/*
	 * Authenticator::setDigits()
	 */

	public function testSetDigits(){
		foreach([6, 8] as $digits){
			Authenticator::setDigits($digits);
			$this->assertEquals($digits, Authenticator::$digits);
		}
	}

	/**
	 * @expectedException \chillerlan\GoogleAuth\AuthenticatorException
	 */
	public function testSetDigitsException(){
		Authenticator::setDigits(7);
	}

	/*
	 * Authenticator::setPeriod()
	 */

	public function testSetPeriod(){
		for($period = 15; $period <= 60; $period++){
			Authenticator::setPeriod($period);
			$this->assertEquals($period, Authenticator::$period);
		}
	}

	/**
	 * @expectedException \chillerlan\GoogleAuth\AuthenticatorException
	 */
	public function testSetPeriodException(){
		Authenticator::setPeriod(1);
	}

	/*
	 * Authenticator::createSecret()
	 */

	public function testCreateSecretDefaultLength(){
		$this->assertEquals(16, strlen(Authenticator::createSecret()));
	}

	public function testCreateSecretWithLength(){
		for($secretLength = 16; $secretLength <= 128; $secretLength++){
			$this->assertEquals($secretLength, strlen(Authenticator::createSecret($secretLength)));
		}
	}

	public function testCreateSecretCheckCharacterSet(){
		$this->assertRegExp('/^['.Base32::RFC3548.']+$/', $this->secret);
	}

	/**
	 * @expectedException \chillerlan\GoogleAuth\AuthenticatorException
	 */
	public function testCreateSecretException(){
		Authenticator::createSecret(10);
	}


	/*
	 * Authenticator::getCode()
	 */

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
		$this->assertEquals($code, Authenticator::getCode($secret, floor($timestamp / Authenticator::$period)));
	}

	/**
	 * @expectedException \chillerlan\GoogleAuth\AuthenticatorException
	 */
	public function testGetCodeException(){
		Authenticator::getCode($this->invalidSecret);
	}

	/*
	 * Authenticator::verifyCode()
	 */

	public function testVerifyCode(){
		$this->assertEquals(true, Authenticator::verifyCode(Authenticator::getCode($this->secret), $this->secret));
		$this->assertEquals(false, Authenticator::verifyCode(Authenticator::getCode($this->secret), $this->falseSecret));
		$this->assertEquals(false, Authenticator::verifyCode('123456', $this->secret));
	}

	public function testVerifyCodeWithTimeslice(){
		$code = Authenticator::getCode($this->secret);
		$timestamp = time();
		$p = Authenticator::$period;

		// first adjacent code (default value)
		$timeslice = floor(($timestamp - (1 * $p)) / $p);
		$this->assertEquals(true, Authenticator::verifyCode($code, $this->secret, $timeslice));

		$timeslice = floor(($timestamp - (2 * $p)) / $p);
		$this->assertEquals(false, Authenticator::verifyCode($code, $this->secret, $timeslice));
	}

	public function testVerifyCodeWithTimesliceAndAdjacent(){
		$code = Authenticator::getCode($this->secret);
		$timestamp = time();
		$adjacent = 100;
		$p = Authenticator::$period;

		for($i = 0; $i <= $adjacent + 1; $i++){
			$timeslice = floor(($timestamp - ($i * $p)) / $p);
			$verify = Authenticator::verifyCode($code, $this->secret, $timeslice, $adjacent);

			$this->assertEquals($i <= $adjacent, $verify);
		}

	}

	// https://github.com/PHPGangsta/GoogleAuthenticator/pull/25
	public function testVerifyCodeWithLeadingZero(){
		$code = Authenticator::getCode($this->secret);
		$this->assertEquals(true, Authenticator::verifyCode($code, $this->secret));

		$code = '0'.$code;
		$this->assertEquals(false, Authenticator::verifyCode($code, $this->secret));
	}

	/**
	 * @expectedException \chillerlan\GoogleAuth\AuthenticatorException
	 */
	public function testVerifyCodeException(){
		Authenticator::verifyCode($this->invalidSecret, Authenticator::getCode($this->secret));
	}


	/*
	 * Authenticator::getUri()
	 */

	public function testGetUri(){
		$values = [
			'secret' => $this->secret,
			'issuer' => $this->issuer,
		];

		$expected = 'otpauth://totp/'.$this->label.'?';
		$this->assertEquals($expected.http_build_query($values), Authenticator::getUri($this->secret, $this->label, $this->issuer));

		Authenticator::setDigits(8);
		$values['digits'] = Authenticator::$digits;
		$this->assertEquals($expected.http_build_query($values), Authenticator::getUri($this->secret, $this->label, $this->issuer));

		Authenticator::setPeriod(45);
		$values['period'] = Authenticator::$period;
		$this->assertEquals($expected.http_build_query($values), Authenticator::getUri($this->secret, $this->label, $this->issuer));

	}

	/**
	 * @expectedException \chillerlan\GoogleAuth\AuthenticatorException
	 */
	public function testGetUriException(){
		Authenticator::getUri($this->invalidSecret, $this->label, $this->issuer);
	}

	/*
	 * Authenticator::getGoogleQr()
	 */
	public function testGetGoogleQr(){
		$label = 'test';
		$issuer = 'chillerlan.net';

		$query = [
			'chs'  => '200x200',
			'chld' => 'M|0',
			'cht'  => 'qr',
			'chl'  => Authenticator::getUri($this->secret, $label, $issuer),
		];

		$expected = 'https://chart.googleapis.com/chart?'.http_build_query($query);

		$this->assertEquals($expected, Authenticator::getGoogleQr($this->secret, $label, $issuer));
	}

}
