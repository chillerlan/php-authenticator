<?php
/**
 * Class AuthenticatorOptionsTest
 *
 * @created      07.03.2019
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2019 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\AuthenticatorTest;

use chillerlan\Authenticator\AuthenticatorOptions;
use chillerlan\Authenticator\Authenticators\AuthenticatorInterface;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

class AuthenticatorOptionsTest extends TestCase{

	protected AuthenticatorOptions $options;

	protected function setUp():void{
		$this->options = new AuthenticatorOptions;
	}

	#[Test]
	public function setDigits():void{
		foreach([6, 8] as $digits){
			$this->options->digits = $digits;
			$this::assertSame($digits, $this->options->digits);
		}
	}

	#[Test]
	public function setDigitsException():void{
		$this->expectException(InvalidArgumentException::class);
		$this->expectExceptionMessage('Invalid code length');

		$this->options->digits = 7;
	}

	#[Test]
	public function setPeriod():void{
		for($period = 15; $period <= 60; $period++){
			$this->options->period = $period;
			$this::assertSame($period, $this->options->period);
		}
	}

	#[Test]
	public function setPeriodException():void{
		$this->expectException(InvalidArgumentException::class);
		$this->expectExceptionMessage('Invalid period');

		$this->options->period = 666;
	}

	#[Test]
	public function setAlgorithm():void{
		foreach(AuthenticatorInterface::HASH_ALGOS as $algo){
			$this->options->algorithm = $algo;
			$this::assertSame($algo, $this->options->algorithm);
		}
	}

	#[Test]
	public function setAlgorithmException():void{
		$this->expectException(InvalidArgumentException::class);
		$this->expectExceptionMessage('Invalid algorithm');

		$this->options->algorithm = 'florps';
	}

	#[Test]
	public function setMode():void{
		foreach(AuthenticatorInterface::MODES as $mode => $class){
			$this->options->mode = $mode;
			$this::assertSame($mode, $this->options->mode);
		}
	}

	#[Test]
	public function setModeException():void{
		$this->expectException(InvalidArgumentException::class);
		$this->expectExceptionMessage('Invalid mode');

		$this->options->mode = 'florps';
	}

	#[Test]
	public function setAdjacent():void{
		for($adjacent = 0; $adjacent <= 10; $adjacent++){
			$this->options->adjacent = $adjacent;
			$this::assertSame($adjacent, $this->options->adjacent);
		}
	}

	#[Test]
	public function setAdjacentException():void{
		$this->expectException(InvalidArgumentException::class);
		$this->expectExceptionMessage('Invalid number of adjacent codes');

		$this->options->adjacent = -1;
	}

	#[Test]
	public function setSecretLength():void{
		for($secretLength = 16; $secretLength <= 1024; $secretLength += 16){
			$this->options->secret_length = $secretLength;
			$this::assertSame($secretLength, $this->options->secret_length);
		}
	}

	#[Test]
	public function setSecretLengthException():void{
		$this->expectException(InvalidArgumentException::class);
		$this->expectExceptionMessage('Invalid secret length: 69420');

		$this->options->secret_length = 69420;
	}

}
