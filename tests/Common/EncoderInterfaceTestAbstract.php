<?php
/**
 * Class EncoderInterfaceTestAbstract
 *
 * @created      02.11.2025
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2025 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\AuthenticatorTest\Common;

use chillerlan\Authenticator\Common\EncoderInterface;
use PHPUnit\Framework\Attributes\{DataProvider, Test};
use PHPUnit\Framework\TestCase;

abstract class EncoderInterfaceTestAbstract extends TestCase{

	protected EncoderInterface $encoder;

	protected function setUp():void{
		$this->encoder = $this->getEncoder();
	}

	abstract protected function getEncoder():EncoderInterface;

	/**
	 * @phpstan-return array<int, array<int, string>>
	 */
	abstract public static function encodeDataProvider():array;

	#[Test]
	#[DataProvider('encodeDataProvider')]
	public function encode(string $str, string $encoded):void{
		$this::assertSame($encoded, $this->encoder::encode($str));
	}

	#[Test]
	#[DataProvider('encodeDataProvider')]
	public function decode(string $str, string $encoded):void{
		$this::assertSame($str, $this->encoder::decode($encoded));
	}

	#[Test]
	#[DataProvider('encodeDataProvider')]
	public function checkCharset(string $str, string $encoded):void{
		$this->expectNotToPerformAssertions();

		$this->encoder::checkCharacterSet($encoded);
	}

}
