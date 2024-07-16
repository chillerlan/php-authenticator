<?php
/**
 * Class Base64Test
 *
 * @created      23.06.2023
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2023 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\AuthenticatorTest\Common;

use chillerlan\Authenticator\Common\Base64;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use function base64_decode;
use function base64_encode;

/**
 *
 */
class Base64Test extends TestCase{

	/**
	 * @phpstan-return array<int, array<int, string>>
	 */
	public static function base64DataProvider():array{
		return [
			['a'                   , 'YQ=='                        ],
			['ab'                  , 'YWI='                        ],
			['abc'                 , 'YWJj'                        ],
			['abcd'                , 'YWJjZA=='                    ],
			['abcde'               , 'YWJjZGU='                    ],
			['abcdef'              , 'YWJjZGVm'                    ],
			['abcdefg'             , 'YWJjZGVmZw=='                ],
			['12345678901234567890', 'MTIzNDU2Nzg5MDEyMzQ1Njc4OTA='],
		];
	}

	#[DataProvider('base64DataProvider')]
	public function testEncode(string $str, string $base64):void{
		$encoded = Base64::encode($str);
		$this::assertSame($base64, $encoded);
		// test against native PHP
		$this::assertSame(base64_encode($str), $encoded);
	}

	#[DataProvider('base64DataProvider')]
	public function testDecode(string $str, string $base64):void{
		$decoded = Base64::decode($base64);

		$this::assertSame($str, $decoded);
		// test against native PHP
		$this::assertSame(base64_decode($base64), $decoded);
	}

	#[DataProvider('base64DataProvider')]
	public function testCheckCharset(string $str, string $base64):void{
		$this->expectNotToPerformAssertions();

		Base64::checkCharacterSet($base64);
	}

	public function testCheckCharsetException():void{
		$this->expectException(InvalidArgumentException::class);
		$this->expectExceptionMessage('Base64 must match RFC4648 character set');

		Base64::checkCharacterSet('YWJjZÄ==...');
	}

}
