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

use chillerlan\Authenticator\Common\{EncoderInterface, Hex};
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;

class HexTest extends EncoderInterfaceTestAbstract{

	protected function getEncoder():EncoderInterface{
		return new Hex;
	}

	public static function encodeDataProvider():array{
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

	#[Test]
	public function checkCharsetException():void{
		$this->expectException(InvalidArgumentException::class);
		$this->expectExceptionMessage('hex string must match hexadecimal character set: 0-9, A-F, a-f');

		Hex::checkCharacterSet('YWJjZÄ==...');
	}

}
