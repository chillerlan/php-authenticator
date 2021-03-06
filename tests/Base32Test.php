<?php
/**
 * @filesource   Base32Test.php
 * @created      29.02.2016
 * @author       Smiley <smiley@chillerlan.net>
 * @copyright    2016 Smiley
 * @license      MIT
 */

namespace chillerlan\AuthenticatorTest;

use chillerlan\Authenticator\{Base32, Base32Exception};
use PHPUnit\Framework\TestCase;

class Base32Test extends TestCase{

	protected Base32 $base32;

	protected function setUp():void{
		$this->base32 = new Base32(Base32::RFC3548);
	}

	public function testSetCharset():void{
		$this->assertSame(Base32::CROCKFORD, $this->base32->setCharset(Base32::CROCKFORD)->getCharset());
	}

	public function testToStringCrockfordCoverage():void{
		$str = $this->base32->setCharset(Base32::CROCKFORD)->toString('6ORK4CSM6MV3EEIS85L46H258S3MGJJB9N750MAJADA5CNTRB5D0');

		$this->assertSame('0123456789ABCDEFGHJKMNPQRSTVWXYZ', $str);
	}

	public function base32DataProvider():array{
		return [
			['a'      , '01100001'                                                , 'ME'          ],
			['ab'     , '0110000101100010'                                        , 'MFRA'        ],
			['abc'    , '011000010110001001100011'                                , 'MFRGG'       ],
			['abcd'   , '01100001011000100110001101100100'                        , 'MFRGGZA'     ],
			['abcde'  , '0110000101100010011000110110010001100101'                , 'MFRGGZDF'    ],
			['abcdef' , '011000010110001001100011011001000110010101100110'        , 'MFRGGZDFMY'  ],
			['abcdefg', '01100001011000100110001101100100011001010110011001100111', 'MFRGGZDFMZTQ'],
		];
	}

	/**
	 * @dataProvider base32DataProvider
	 */
	public function testStr2Bin(string $str, string $bin):void{
		$this->assertSame($bin, $this->base32->str2bin($str));
	}

	/**
	 * @dataProvider base32DataProvider
	 */
	public function testBin2Str(string $str, string $bin):void{
		$this->assertSame($str, $this->base32->bin2str($bin));
	}

	/**
	 * @dataProvider base32DataProvider
	 * @noinspection PhpUnusedParameterInspection
	 */
	public function testFromBin(string $str, string $bin, string $base32):void{
		$this->assertSame($base32, $this->base32->fromBin($bin));
	}

	/**
	 * @dataProvider base32DataProvider
	 * @noinspection PhpUnusedParameterInspection
	 */
	public function testToBin(string $str, string $bin, string $base32):void{
		$this->assertSame($bin, $this->base32->toBin($base32));
	}

	/**
	 * @dataProvider base32DataProvider
	 * @noinspection PhpUnusedParameterInspection
	 */
	public function testFromString(string $str, string $bin, string $base32):void{
		$this->assertSame($base32, $this->base32->fromString($str));
	}

	/**
	 * @dataProvider base32DataProvider
	 * @noinspection PhpUnusedParameterInspection
	 */
	public function testToString(string $str, string $bin, string $base32){
		$this->assertSame($str, $this->base32->toString($base32));
	}

	public function testSetCharsetException():void{
		$this->expectException(Base32Exception::class);
		$this->expectExceptionMessage('Length must be exactly 32');

		$this->base32->setCharset('florps');
	}

	public function testCheckBinLengthException():void{
		$this->expectException(Base32Exception::class);
		$this->expectExceptionMessage('Length must be divisible by 8');

		$this->base32->fromBin('0100110');
	}

	public function testCheckBinException():void{
		$this->expectException(Base32Exception::class);
		$this->expectExceptionMessage('Only 0 and 1 are permitted');

		$this->base32->fromBin('01001102');
	}

	public function testToBinCharsetException():void{
		$this->expectException(Base32Exception::class);
		$this->expectExceptionMessage('Must match character set');

		$this->base32->toBin('MFRGGZDFMZTÖ');
	}

}
