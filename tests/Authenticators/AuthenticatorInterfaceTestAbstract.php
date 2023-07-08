<?php
/**
 * Class AuthenticatorInterfaceTestAbstract
 *
 * @created      19.06.2023
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2023 smiley
 * @license      MIT
 */

namespace chillerlan\AuthenticatorTest\Authenticators;

use chillerlan\Authenticator\AuthenticatorOptions;
use chillerlan\Authenticator\Authenticators\AuthenticatorInterface;
use chillerlan\Authenticator\Common\Base32;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use function strlen;

/**
 *
 */
abstract class AuthenticatorInterfaceTestAbstract extends TestCase{

	protected AuthenticatorOptions   $options;
	protected AuthenticatorInterface $authenticatorInterface;

	protected const rawsecret = '12345678901234567890';
	protected const secret    = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

	abstract protected function getInstance(AuthenticatorOptions $options):AuthenticatorInterface;

	protected function setUp():void{
		$this->options                = new AuthenticatorOptions;
		$this->authenticatorInterface = $this->getInstance($this->options);
	}

	public function testSetGetSecret():void{
		$this->authenticatorInterface->setSecret($this::secret);

		$secret = $this->authenticatorInterface->getSecret();

		$this::assertSame($this::secret, $secret);
		$this::assertSame($this::rawsecret, Base32::decode($secret));
	}

	public function testSetEmptySecretException():void{
		$this->expectException(InvalidArgumentException::class);
		$this->expectExceptionMessage('The given secret string is empty');

		$this->authenticatorInterface->setSecret('');
	}

	public function testSetInvalidSecretException():void{
		$this->expectException(InvalidArgumentException::class);

		$this->authenticatorInterface->setSecret('This_is_an_invalid_secret_phrase!');
	}

	public function testGetSecretException():void{
		$this->expectException(RuntimeException::class);
		$this->expectExceptionMessage('No secret set');

		$this->authenticatorInterface->getSecret();
	}

	public function testCreateSecretDefaultLength():void{
		$this::assertSame(
			$this->options->secret_length,
			strlen(Base32::decode($this->authenticatorInterface->createSecret()))
		);
	}

	public function testCreateSecretWithLength():void{

		for($secretLength = 16; $secretLength <= 512; $secretLength += 8){
			$secret = Base32::decode($this->authenticatorInterface->createSecret($secretLength));

			$this::assertSame($secretLength, strlen($secret));
		}

	}

	public function testCreateSecretCheckCharacterSet():void{
		$secret = $this->authenticatorInterface->createSecret(32);

		$this::assertMatchesRegularExpression('/^['.Base32::CHARSET.']+$/', $secret);
	}

	public function testCreateSecretException():void{
		$this->expectException(InvalidArgumentException::class);
		$this->expectExceptionMessage('Invalid secret length');

		$this->authenticatorInterface->createSecret(10);
	}

	public function testGetHMACWithoutSecretException():void{
		$this->expectException(RuntimeException::class);
		$this->expectExceptionMessage('No secret given');

		$this->authenticatorInterface->getHMAC(69);
	}

	// https://github.com/PHPGangsta/GoogleAuthenticator/pull/25
	public function testVerifyCodeWithLeadingZero():void{
		$this->authenticatorInterface->setSecret($this::secret);

		$code = $this->authenticatorInterface->code();

		$this::assertTrue($this->authenticatorInterface->verify($code));
		$this::assertFalse($this->authenticatorInterface->verify('0'.$code));
	}

	// coverage
	public function testGetServertime():void{
		$this->options->useLocalTime = false;

		$servertime = $this->authenticatorInterface->getServerTime();
		$this::assertMatchesRegularExpression('/^\d+$/', (string)$servertime);

		$this->options->forceTimeRefresh = false;

		$servertime = $this->authenticatorInterface->getServerTime();
		$this::assertMatchesRegularExpression('/^\d+$/', (string)$servertime);
	}

}
