<?php
/**
 * Class Base32Test
 *
 * @created      29.02.2016
 * @author       Smiley <smiley@chillerlan.net>
 * @copyright    2016 Smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\AuthenticatorTest\Common;

use chillerlan\Authenticator\Common\{Base32, EncoderInterface};
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;

class Base32Test extends EncoderInterfaceTestAbstract{

	protected function getEncoder():EncoderInterface{
		return new Base32;
	}

	public static function encodeDataProvider():array{
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

	#[Test]
	public function checkCharsetException():void{
		$this->expectException(InvalidArgumentException::class);
		$this->expectExceptionMessage('Base32 must match RFC3548 character set');

		$this->encoder::checkCharacterSet('MFRGGZDFMZTÖ');
	}

}
