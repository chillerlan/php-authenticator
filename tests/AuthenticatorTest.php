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

	protected function setUp(){
		$this->secret = Authenticator::createSecret();
	}

	protected function tearDown(){
		Authenticator::setDigits(6);
		Authenticator::setPeriod(30);
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

	/*
	 * Authenticator::setPeriod()
	 */

	public function testSetPeriod(){
		for($period = 15; $period <= 60; $period++){
			Authenticator::setPeriod($period);
			$this->assertEquals($period, Authenticator::$period);
		}
	}

	/*
	 * Authenticator::createSecret()
	 */

	public function testCreateSecretDefaultLength(){
		$this->assertEquals(16, strlen(Authenticator::createSecret()));
	}

	public function testCreateSecretWithLength(){
		for($secretLength = 1; $secretLength <= 100; $secretLength++){
			$this->assertEquals($secretLength, strlen(Authenticator::createSecret($secretLength)));
		}
	}

	public function testCreateSecretCheckCharacterSet(){
		$this->assertRegExp('/^['.Base32::RFC3548.']+$/', $this->secret);
	}

	/*
	 * Authenticator::getCode()
	 */

	public function codeProvider(){
		// secret, time, code
		return [
			['SECRETTEST234567',          0, '730741'],
			['SECRETTEST234567', 1385909245, '040137'],
			['SECRETTEST234567', 1378934578, '341779'],
			['SECRETTEST234567', 1449438863, '889844'],
		];
	}

	/**
	 * @dataProvider codeProvider
	 */
	public function testGetCode($secret, $timestamp, $code){
		$this->assertEquals($code, Authenticator::getCode($secret, floor($timestamp / Authenticator::$period)));
	}

	/*
	 * Authenticator::verifyCode()
	 */

	public function testVerifyCode(){
		$this->assertEquals(true, Authenticator::verifyCode(Authenticator::getCode($this->secret), $this->secret));
		$this->assertEquals(false, Authenticator::verifyCode(Authenticator::getCode($this->secret), 'SECRETTEST234567'));
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

			if($i === $adjacent + 1){
				$this->assertEquals(false, Authenticator::verifyCode($code, $this->secret, $timeslice, $adjacent));
			}
			else{
				$this->assertEquals(true, Authenticator::verifyCode($code, $this->secret, $timeslice, $adjacent));
			}

		}

	}

	/*
	 * Authenticator::getUri()
	 */

	public function testGetUri(){
		$label = 'test';
		$issuer = 'chillerlan.net';

		$values = [
			'secret' => $this->secret,
			'issuer' => $issuer,
		];

		$expected = 'otpauth://totp/'.$label.'?';
		$this->assertEquals($expected.http_build_query($values), Authenticator::getUri($this->secret, $label, $issuer));

		Authenticator::setDigits(8);
		$values['digits'] = Authenticator::$digits;
		$this->assertEquals($expected.http_build_query($values), Authenticator::getUri($this->secret, $label, $issuer));

		Authenticator::setPeriod(45);
		$values['period'] = Authenticator::$period;
		$this->assertEquals($expected.http_build_query($values), Authenticator::getUri($this->secret, $label, $issuer));

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
