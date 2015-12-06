<?php
/**
 * class.Base32.php5
 * Provide Base32 conversion class
 *
 * @author    Shannon Wynter {@link http://fremnet.net/contact}
 * @version   0.3
 * @copyright Copyright &copy; 2006 Shannon Wynter
 * @link      http://fremnet.net
 *
 * Class to provide base32 encoding/decoding of strings
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * ChangeLog
 * -----------
 * version 0.3, 2015-12-06, smiley {@link https://github.com/codemasher}
 *  - static all the things!
 * version 0.2, 2008-08-07, Shannon Wynter {@link http://fremnet.net/contact}
 *  - Fixed transposition of Y and Z in csRFC3548
 * version 0.1, 2006-06-22, Shannon Wynter {@link http://fremnet.net/contact}
 *  - Initial release
 *
 * Notes
 * -----------
 * For dealing with humans it's probably best to use csSafe rather then csRFC3548
 *
 */

namespace chillerlan\GoogleAuth;

use Exception;

/**
 * Class Base32
 *
 * Provides Base32 conversion
 *
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
	const csSafe = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

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
	const cs09AV = '0123456789ABCDEFGHIJKLMNOPQRSTUV';

	/**
	 * charset
	 *
	 * Internal holder of the current character set.
	 *
	 * @access protected
	 * @var string
	 */
	public static $charset = self::RFC3548;

	/**
	 * setCharset
	 *
	 * Used to set the internal _charset variable
	 * I've left it so that people can arbirtrarily set their
	 * own charset
	 *
	 * Can be called with:
	 * * Base32::RFC3548
	 * * Base32::csSafe
	 * * Base32::cs09AV
	 *
	 * @param string $charset The character set you want to use
	 *
	 * @throws \Exception
	 */
	public static function setCharset($charset = self::RFC3548){
		if(strlen($charset) === 32){
			self::$charset = strtoupper($charset);
		}
		else{
			throw new Exception('Length must be exactly 32');
		}
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
	public static function str2bin($str){
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
	 * @throws \Exception
	 */
	public static function bin2str($str){
		if(strlen($str) % 8 > 0){
			throw new Exception('Length must be divisible by 8');
		}

		if(!preg_match('/^[01]+$/', $str)){
			throw new Exception('Only 0\'s and 1\'s are permitted');
		}

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
	 * @throws exception
	 */
	public static function fromBin($str){
		if(strlen($str) % 8 > 0){
			throw new Exception('Length must be divisible by 8');
		}

		if(!preg_match('/^[01]+$/', $str)){
			throw new Exception('Only 0\'s and 1\'s are permitted');
		}

		// Base32 works on the first 5 bits of a byte, so we insert blanks to pad it out
		$str = preg_replace('/(.{5})/', '000$1', $str);

		// We need a string divisible by 5
		$length = strlen($str);
		$rbits = $length&7;

		if($rbits > 0){
			// Excessive bits need to be padded
			$ebits = substr($str, $length - $rbits);
			$str = substr($str, 0, $length - $rbits).'000'.$ebits.str_repeat('0', 5 - strlen($ebits));
		}

		preg_match_all('/.{8}/', $str, $chrs);

		$chrs = array_map(function($str){
			return self::$charset[bindec($str)];
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
	 * @throws \Exception
	 */
	public static function toBin($str){
		if(!preg_match('/^['.self::$charset.']+$/', $str)){
			throw new Exception('Must match character set');
		}

		// Convert the base32 string back to a binary string
		$str = array_map(function ($chr){
			return sprintf('%08b', strpos(self::$charset, $chr));
		}, str_split($str));

		// Remove the extra 0's we added
		$str = preg_replace('/000(.{5})/', '$1', implode('', $str));

		// Unpad if nessicary
		$length = strlen($str);
		$rbits = $length&7;

		if($rbits > 0){
			$str = substr($str, 0, $length - $rbits);
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
	public static function fromString($str){
		return self::fromBin(self::str2bin($str));
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
	public static function toString($str){
		$str = strtoupper($str);

		// csSave actually has to be able to consider extra characters
		if(self::$charset === self::csSafe){
			$str = str_replace('O', '0', $str);
			$str = str_replace(['I', 'L'], '1', $str);
		}

		return self::bin2str(self::toBin($str));
	}

}
