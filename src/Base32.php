<?php
/**
 * Class Base32
 *
 * @filesource   Base32.php
 * @package      chillerlan\Authenticator
 * @author       Shannon Wynter {@link http://fremnet.net/contact}
 * @author       Smiley <smiley@chillerlan.net>
 * @copyright    Copyright (c) 2006 Shannon Wynter
 */

namespace chillerlan\Authenticator;

/**
 * Class to provide base32 encoding/decoding of strings
 *
 * @property string $charset
 */
class Base32{

	/**
	 * RFC3548
	 *
	 * The character set as defined by RFC3548
	 *
	 * @link http://www.ietf.org/rfc/rfc3548.txt
	 */
	const RFC3548 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * csSafe
	 *
	 * This character set is designed to be more human friendly
	 * For example: i, I, L, l and 1 all map to 1
	 * Also: there is no U - to help prevent offencive output
	 *
	 * @link http://www.crockford.com/wrmg/base32.html
	 *
	 */
	const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

	/**
	 * cs09AV
	 *
	 * This character set follows the example of the hex
	 * character set and is included to make this class
	 * compatible with MIME::Base32
	 *
	 * @link http://search.cpan.org/~danpeder/MIME-Base32-1.01/Base32.pm
	 *
	 */
	const MIME_09AV = '0123456789ABCDEFGHIJKLMNOPQRSTUV';

	/**
	 * charset
	 *
	 * Internal holder of the current character set.
	 *
	 * @var string
	 */
	protected $charset = self::RFC3548;

	/**
	 * Base32 constructor.
	 *
	 * @param string $charset
	 */
	public function __construct(string $charset = null){

		if($charset !== null){
			$this->setCharset($charset);
		}

	}

	/**
	 * setCharset
	 *
	 * Used to set the internal $charset variable
	 * I've left it so that people can arbirtrarily set their
	 * own charset
	 *
	 * @param string $charset The character set you want to use
	 *
	 * @return \chillerlan\Authenticator\Base32
	 * @throws \chillerlan\Authenticator\Base32Exception
	 */
	public function setCharset(string $charset):Base32 {

		if(strlen($charset) !== 32){
			throw new Base32Exception('Length must be exactly 32');
		}

		$this->charset = strtoupper($charset);

		return $this;
	}

	/**
	 * @return string
	 */
	public function getCharset():string {
		return $this->charset;
	}

	/**
	 * str2bin
	 *
	 * Converts any ascii string to a binary string
	 *
	 * @param string $str The string you want to convert
	 *
	 * @return string String of 0's and 1's
	 */
	public function str2bin(string $str):string {
		$chrs = unpack('C*', $str);

		return vsprintf(str_repeat('%08b', count($chrs)), $chrs);
	}

	/**
	 * bin2str
	 *
	 * Converts a binary string to an ascii string
	 *
	 * @param string $str The string of 0's and 1's you want to convert
	 *
	 * @return string The ascii output
	 */
	public function bin2str(string $str):string {
		$this->checkLength($str);
		$this->checkBin($str);

		preg_match_all('/.{8}/', $str, $chrs);
		$chrs = array_map('bindec', $chrs[0]);

		// I'm just being slack here
		array_unshift($chrs, 'C*');

		return call_user_func_array('pack', $chrs);
	}

	/**
	 * fromBin
	 *
	 * Converts a correct binary string to base32
	 *
	 * @param string $str The string of 0's and 1's you want to convert
	 *
	 * @return string String encoded as base32
	 */
	public function fromBin(string $str):string {
		$this->checkLength($str);
		$this->checkBin($str);

		// Base32 works on the first 5 bits of a byte, so we insert blanks to pad it out
		$str = preg_replace('/(.{5})/', '000$1', $str);

		// We need a string divisible by 5
		$length = strlen($str);
		$rbits = $length&7;

		if($rbits > 0){
			// Excessive bits need to be padded
			$ebits = substr($str, $length-$rbits);
			$str = substr($str, 0, $length-$rbits).'000'.$ebits.str_repeat('0', 5-strlen($ebits));
		}

		preg_match_all('/.{8}/', $str, $chrs);

		$chrs = array_map(function($str){
			return $this->charset[bindec($str)];
		}, $chrs[0]);

		return implode('', $chrs);
	}

	/**
	 * toBin
	 *
	 * Accepts a base32 string and returns an ascii binary string
	 *
	 * @param string $str The base32 string to convert
	 *
	 * @return string Ascii binary string
	 */
	public function toBin(string $str):string {
		$this->checkCharacterSet($str);

		// Convert the base32 string back to a binary string
		$str = array_map(function($chr){
			return sprintf('%08b', strpos($this->charset, $chr));
		}, str_split($str));

		// Remove the extra 0's we added
		$str = preg_replace('/000(.{5})/', '$1', implode('', $str));

		// Unpad if nessicary
		$length = strlen($str);
		$rbits = $length&7;

		if($rbits > 0){
			$str = substr($str, 0, $length-$rbits);
		}

		return $str;
	}

	/**
	 * fromString
	 *
	 * Convert any string to a base32 string
	 * This should be binary safe...
	 *
	 * @param string $str The string to convert
	 *
	 * @return string The converted base32 string
	 */
	public function fromString(string $str):string {
		return $this->fromBin($this->str2bin($str));
	}

	/**
	 * toString
	 *
	 * Convert any base32 string to a normal sctring
	 * This should be binary safe...
	 *
	 * @param string $str The base32 string to convert
	 *
	 * @return string The normal string
	 */
	public function toString(string $str):string {
		$str = strtoupper($str);

		// csSave actually has to be able to consider extra characters
		if($this->charset === $this::CROCKFORD){
			$str = str_replace('O', '0', $str);
			$str = str_replace(['I', 'L'], '1', $str);
		}

		return $this->bin2str($this->toBin($str));
	}

	/**
	 * @param string $str
	 *
	 * @return void
	 * @throws \chillerlan\Authenticator\Base32Exception
	 */
	protected function checkLength(string $str){

		if(strlen($str)%8 > 0){
			throw new Base32Exception('Length must be divisible by 8');
		}

	}

	/**
	 * @param string $str
	 *
	 * @return void
	 * @throws \chillerlan\Authenticator\Base32Exception
	 */
	protected function checkBin(string $str){

		if(!preg_match('/^[01]+$/', $str)){
			throw new Base32Exception('Only 0 and 1 are permitted');
		}

	}

	/**
	 * @param string $str
	 *
	 * @return void
	 * @throws \chillerlan\Authenticator\Base32Exception
	 */
	protected function checkCharacterSet(string $str){

		if(!preg_match('/^['.$this->charset.']+$/', $str)){
			throw new Base32Exception('Must match character set');
		}

	}

}
