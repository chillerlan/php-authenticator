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

use chillerlan\Authenticator\Common\{Base64, EncoderInterface};
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;

class Base64Test extends EncoderInterfaceTestAbstract{

	protected function getEncoder():EncoderInterface{
		return new Base64;
	}

	public static function encodeDataProvider():array{
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

	#[Test]
	public function checkCharsetException():void{
		$this->expectException(InvalidArgumentException::class);
		$this->expectExceptionMessage('Base64 must match RFC4648 character set');

		$this->encoder::checkCharacterSet('YWJjZÄ==...');
	}

}
