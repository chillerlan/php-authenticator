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

class AuthenticatorTest extends PHPUnit_Framework_TestCase{

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
		$secret = Authenticator::createSecret();
		$this->assertEquals(16, strlen($secret));
	}

	public function testCreateSecretWithLength(){
		for ($secretLength = 1; $secretLength <= 100; $secretLength++) {
			$secret = Authenticator::createSecret($secretLength);
			$this->assertEquals($secretLength, strlen($secret));
		}
	}

	/*
	 * Authenticator::verifyCode()
	 */
	public function testVerifyCodeWithTimeslice(){
		Authenticator::setPeriod(30);
		$secret = Authenticator::createSecret();
		$code = Authenticator::getCode($secret);
		$timestamp = time();
		$adjacent = 100;

		for($i = 0; $i <= $adjacent+1; $i++){
			$timestamp = $timestamp - $i * Authenticator::$period;
			$timeslice = floor($timestamp / Authenticator::$period);

/*
			print_r([
				$i,
				$timestamp,
				$timeslice,
				(int)Authenticator::verifyCode($code, $secret, $timeslice, $adjacent),
			]);
*/

			if($i === $adjacent+1){
				$this->assertEquals(false, Authenticator::verifyCode($code, $secret, $timeslice, $adjacent));
			}
			else{
				$this->assertEquals(true, Authenticator::verifyCode($code, $secret, $timeslice, $adjacent));
			}

		}

	}

}
