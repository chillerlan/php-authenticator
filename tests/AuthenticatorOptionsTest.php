<?php
/**
 * Class AuthenticatorOptionsTest
 *
 * @filesource   AuthenticatorOptionsTest.php
 * @created      07.03.2019
 * @package      chillerlan\AuthenticatorTest
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2019 smiley
 * @license      MIT
 */

namespace chillerlan\AuthenticatorTest;

use chillerlan\Authenticator\{AuthenticatorException, AuthenticatorOptions};
use PHPUnit\Framework\TestCase;

class AuthenticatorOptionsTest extends TestCase{

	protected AuthenticatorOptions $options;

	protected function setUp():void{
		$this->options = new AuthenticatorOptions;
	}

	public function testSetDigits():void{
		foreach([6, 8] as $digits){
			$this->options->digits = $digits;
			$this->assertSame($digits, $this->options->digits);
		}
	}

	public function testSetDigitsException():void{
		$this->expectException(AuthenticatorException::class);
		$this->expectExceptionMessage('Invalid code length');

		$this->options->digits = 7;
	}

	public function testSetPeriod():void{
		for($period = 15; $period <= 60; $period++){
			$this->options->period = $period;
			$this->assertSame($period, $this->options->period);
		}
	}

	public function testSetPeriodException():void{
		$this->expectException(AuthenticatorException::class);
		$this->expectExceptionMessage('Invalid period');

		$this->options->period = 666;
	}

	public function testSetAlgorithm():void{
		foreach(['sha1', 'sha256', 'sha512'] as $algo){
			$this->options->algorithm = $algo;
			$this->assertSame(strtoupper($algo), $this->options->algorithm);
		}
	}

	public function testSetAlgorithmException():void{
		$this->expectException(AuthenticatorException::class);
		$this->expectExceptionMessage('Invalid algorithm');

		$this->options->algorithm = 'florps';
	}

	public function testSetMode():void{
		foreach(['totp', 'hotp'] as $mode){
			$this->options->mode = $mode;
			$this->assertSame($mode, $this->options->mode);
		}
	}

	public function testSetModeException():void{
		$this->expectException(AuthenticatorException::class);
		$this->expectExceptionMessage('Invalid mode');

		$this->options->mode = 'florps';
	}

	public function testSetAdjacent():void{
		for($adjacent = 0; $adjacent <= 10; $adjacent++){
			$this->options->adjacent = $adjacent;
			$this->assertSame($adjacent, $this->options->adjacent);
		}
	}

	public function testSetAdjacentException():void{
		$this->expectException(AuthenticatorException::class);
		$this->expectExceptionMessage('Invalid adjacent');

		$this->options->adjacent = -1;
	}

}
