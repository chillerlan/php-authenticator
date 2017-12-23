<?php
/**
 * @filesource   Base32Test.php
 * @created      29.02.2016
 * @author       Smiley <smiley@chillerlan.net>
 * @copyright    2016 Smiley
 * @license      MIT
 */

namespace chillerlan\AuthenticatorTest;

use chillerlan\Authenticator\Base32;
use PHPUnit\Framework\TestCase;

class Base32Test extends TestCase{

	/**
	 * @var \chillerlan\Authenticator\Base32
	 */
	protected $base32;

	protected function setUp(){
		$this->base32 = new Base32(Base32::RFC3548);
	}

	public function testSetCharset(){
		$this->assertSame(Base32::CROCKFORD, $this->base32->setCharset(Base32::CROCKFORD)->getCharset());
	}

	public function testToStringCrockfordCoverage(){
		$this->assertSame('0123456789ABCDEFGHJKMNPQRSTVWXYZ', $this->base32->setCharset(Base32::CROCKFORD)->toString('6ORK4CSM6MV3EEIS85L46H258S3MGJJB9N750MAJADA5CNTRB5D0'));
	}

	public function base32DataProvider(){
		return [
			['a',                                                       '01100001', 'ME'          ],
			['ab',                                              '0110000101100010', 'MFRA'        ],
			['abc',                                     '011000010110001001100011', 'MFRGG'       ],
			['abcd',                            '01100001011000100110001101100100', 'MFRGGZA'     ],
			['abcde',                   '0110000101100010011000110110010001100101', 'MFRGGZDF'    ],
			['abcdef',          '011000010110001001100011011001000110010101100110', 'MFRGGZDFMY'  ],
			['abcdefg', '01100001011000100110001101100100011001010110011001100111', 'MFRGGZDFMZTQ'],
		];
	}

	/**
	 * @dataProvider base32DataProvider
	 */
	public function testStr2Bin($str, $bin){
		$this->assertSame($bin, $this->base32->str2bin($str));
	}

	/**
	 * @dataProvider base32DataProvider
	 */
	public function testBin2Str($str, $bin){
		$this->assertSame($str, $this->base32->bin2str($bin));
	}

	/**
	 * @dataProvider base32DataProvider
	 */
	public function testFromBin($str, $bin, $base32){
		$this->assertSame($base32, $this->base32->fromBin($bin));
	}

	/**
	 * @dataProvider base32DataProvider
	 */
	public function testToBin($str, $bin, $base32){
		$this->assertSame($bin, $this->base32->toBin($base32));
	}

	/**
	 * @dataProvider base32DataProvider
	 */
	public function testFromString($str, $bin, $base32){
		$this->assertSame($base32, $this->base32->fromString($str));
	}

	/**
	 * @dataProvider base32DataProvider
	 */
	public function testToString($str, $bin, $base32){
		$this->assertSame($str, $this->base32->toString($base32));
	}

	/**
	 * @expectedException \chillerlan\Authenticator\Base32Exception
	 * @expectedExceptionMessage Length must be exactly 32
	 */
	public function testSetCharsetException(){
		$this->base32->setCharset('florps');
	}

	/**
	 * @expectedException \chillerlan\Authenticator\Base32Exception
	 * @expectedExceptionMessage Length must be divisible by 8
	 */
	public function testCheckBinLengthException(){
		$this->base32->fromBin('0100110');
	}

	/**
	 * @expectedException \chillerlan\Authenticator\Base32Exception
	 * @expectedExceptionMessage Only 0 and 1 are permitted
	 */
	public function testCheckBinException(){
		$this->base32->fromBin('01001102');
	}

	/**
	 * @expectedException \chillerlan\Authenticator\Base32Exception
	 * @expectedExceptionMessage Must match character set
	 */
	public function testToBinCharsetException(){
		$this->base32->toBin('MFRGGZDFMZTÖ');
	}

}
