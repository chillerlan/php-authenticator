<?php
/**
 * Class HOTPTest
 *
 * @created      19.06.2023
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2023 smiley
 * @license      MIT
 */

namespace chillerlan\AuthenticatorTest\Authenticators;

use chillerlan\Authenticator\Authenticators\{AuthenticatorInterface, HOTP};
use Generator;
use function bin2hex;
use function sprintf;

/**
 *
 */
class HOTPTest extends AuthenticatorInterfaceTestAbstract{

	/**
	 * @see https://tools.ietf.org/html/rfc4226#page-32
	 */
	const rfc4226Vectors = [
		[0, 'cc93cf18508d94934c64b65d8ba7667fb7cde4b0', 1284755224, '755224'],
		[1, '75a48a19d4cbe100644e8ac1397eea747a2d33ab', 1094287082, '287082'],
		[2, '0bacb7fa082fef30782211938bc1c5e70416ff44',  137359152, '359152'],
		[3, '66c28227d03a2d5529262ff016a1e6ef76557ece', 1726969429, '969429'],
		[4, 'a904c900a64b35909874b33e61c5938a8e15ed1c', 1640338314, '338314'],
		[5, 'a37e783d7b7233c083d4f62926c7a25f238d0316',  868254676, '254676'],
		[6, 'bc9cd28561042c83f219324d3c607256c03272ae', 1918287922, '287922'],
		[7, 'a4fb960c0bc06e1eabb804e5b397cdc4b45596fa',   82162583, '162583'],
		[8, '1b3c89f65e6c9e883012052823443f048b4332db',  673399871, '399871'],
		[9, '1637409809a679dc698207310c8c7fc07290d9e5',  645520489, '520489'],
	];

	protected function getInstance():AuthenticatorInterface{
		return new HOTP;
	}

	public static function hotpVectors():Generator{
		foreach(self::rfc4226Vectors as list($counter, $hmac, $code, $hotp)){
			yield sprintf('value: %d', $counter) => [$counter, $hmac, $code, $hotp];
		}
	}

	/**
	 * @link https://github.com/winauth/winauth/issues/449#issuecomment-353670105
	 *
	 * @dataProvider hotpVectors
	 */
	public function testHOTP(int $counter, string $hmac, int $code, string $hotp){
		$this->authenticatorInterface->setSecret($this::secret);

		$hmac_intermediate = $this->authenticatorInterface->getHMAC($counter);
		$code_intermediate = $this->authenticatorInterface->getCode($hmac_intermediate);

		$this::assertSame($hmac, bin2hex($hmac_intermediate));
		$this::assertSame($code, $code_intermediate);

		$this::assertTrue($this->authenticatorInterface->verify($hotp, $counter));
	}

}
