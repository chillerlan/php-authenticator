<?php
/**
 * Class Base32Test
 *
 * @created      29.02.2016
 * @author       Smiley <smiley@chillerlan.net>
 * @copyright    2016 Smiley
 * @license      MIT
 */

namespace chillerlan\AuthenticatorTest\Common;

use chillerlan\Authenticator\Common\Base32;
use Exception;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

class Base32Test extends TestCase{

	public static function base32DataProvider(){
		return [
			['a'                   , 'ME'                              ],
			['ab'                  , 'MFRA'                            ],
			['abc'                 , 'MFRGG'                           ],
			['abcd'                , 'MFRGGZA'                         ],
			['abcde'               , 'MFRGGZDF'                        ],
			['abcdef'              , 'MFRGGZDFMY'                      ],
			['abcdefg'             , 'MFRGGZDFMZTQ'                    ],
			['12345678901234567890', 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'],
		];
	}

	/**
	 * @param string $str
	 * @param string $base32
	 *
	 * @return void
	 *
	 * @dataProvider base32DataProvider
	 */
	public function testEncode($str, $base32){
		$this::assertSame($base32, Base32::encode($str));
	}

	/**
	 * @param string $str
	 * @param string $base32
	 *
	 * @return void
	 *
	 * @dataProvider base32DataProvider
	 */
	public function testDecode($str, $base32){
		$this::assertSame($str, Base32::decode($base32));
	}

	/**
	 * @param string $str
	 * @param string $base32
	 *
	 * @return void
	 *
	 * @dataProvider base32DataProvider
	 */
	public function testCheckCharset($str, $base32){
		try{
			Base32::checkCharacterSet($base32);

			$this::assertTrue(true);
		}
		catch(Exception $e){
			$this->fail($e->getMessage());
		}
	}

	public function testCheckCharsetException(){
		$this->expectException(InvalidArgumentException::class);
		$this->expectExceptionMessage('Base32 must match RFC3548 character set');

		Base32::checkCharacterSet('MFRGGZDFMZTÖ');
	}

}
