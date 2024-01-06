<?php
/**
 * Class BattleNet
 *
 * @created      28.06.2023
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2023 smiley
 * @license      MIT
 *
 * @noinspection PhpComposerExtensionStubsInspection
 */

namespace chillerlan\Authenticator\Authenticators;

use chillerlan\Authenticator\Common\Hex;
use RuntimeException;
use SensitiveParameter;
use function str_pad;
use const STR_PAD_LEFT;

/**
 * @see https://github.com/winauth/winauth/blob/master/Authenticator/BattleNetAuthenticator.cs
 * @see https://github.com/krtek4/php-bma
 * @see https://github.com/jleclanche/python-bna/issues/38
 */
final class BattleNet extends TOTP{

	/**
	 * @inheritDoc
	 */
	public function setSecret(string $encodedSecret):AuthenticatorInterface{
		$this->secret = Hex::decode($this->checkEncodedSecret($encodedSecret));

		return $this;
	}

	/**
	 * @inheritDoc
	 */
	public function getSecret():string{

		if($this->secret === null){
			throw new RuntimeException('No secret set');
		}

		return Hex::encode($this->secret);
	}

	/**
	 * @inheritDoc
	 * @codeCoverageIgnore
	 */
	public function createSecret(int $length = null):string{
		throw new RuntimeException('Not implemented');
	}

	/**
	 * @inheritDoc
	 */
	public function getCounter(int $data = null):int{
		// the period is fixed to 30 seconds for Battle.net
		$this->options->period = 30;

		return parent::getCounter($data);
	}

	/**
	 * @inheritDoc
	 */
	public function getHMAC(int $counter):string{
		// algorithm is fixed to sha1 for Battle.net
		$this->options->algorithm = self::ALGO_SHA1;

		return parent::getHMAC($counter);
	}

	/**
	 * @inheritDoc
	 */
	public function getOTP(#[SensitiveParameter] int $code):string{
		$code %= 100000000;

		// length is fixed to 8 for Battle.net
		return str_pad((string)$code, 8, '0', STR_PAD_LEFT);
	}

}
