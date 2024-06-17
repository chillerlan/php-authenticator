<?php
/**
 * Class HexTest
 *
 * @created      23.06.2023
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2023 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\AuthenticatorTest\Common;

use chillerlan\Authenticator\Common\Hex;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use function bin2hex;
use function hex2bin;

/**
 *
 */
class HexTest extends TestCase{

	public static function hexDataProvider():array{
		return [
			['a'                   , '61'                                      ],
			['ab'                  , '6162'                                    ],
			['abc'                 , '616263'                                  ],
			['abcd'                , '61626364'                                ],
			['abcde'               , '6162636465'                              ],
			['abcdef'              , '616263646566'                            ],
			['abcdefg'             , '61626364656667'                          ],
			['12345678901234567890', '3132333435363738393031323334353637383930'],
		];
	}

	/**
	 * @dataProvider hexDataProvider
	 */
	public function testEncode(string $str, string $hex):void{
		$encoded = Hex::encode($str);
		$this::assertSame($hex, $encoded);
		// test against native PHP
		$this::assertSame(bin2hex($str), $encoded);
	}

	/**
	 * @dataProvider hexDataProvider
	 */
	public function testDecode(string $str, string $hex):void{
		$decoded = Hex::decode($hex);

		$this::assertSame($str, $decoded);
		// test against native PHP
		$this::assertSame(hex2bin($hex), $decoded);
	}

	/**
	 * @dataProvider hexDataProvider
	 */
	public function testCheckCharset(string $str, string $hex):void{
		$this->expectNotToPerformAssertions();

		Hex::checkCharacterSet($hex);
	}

	public function testCheckCharsetException():void{
		$this->expectException(InvalidArgumentException::class);
		$this->expectExceptionMessage('hex string must match hexadecimal character set: 0-9, A-F, a-f');

		Hex::checkCharacterSet('YWJjZÄ==...');
	}

}
