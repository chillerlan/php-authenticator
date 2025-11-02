<?php
/**
 * Class AuthenticatorInterfaceTestAbstract
 *
 * @created      19.06.2023
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2023 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\AuthenticatorTest\Authenticators;

use chillerlan\Authenticator\AuthenticatorOptions;
use chillerlan\Authenticator\Authenticators\AuthenticatorInterface;
use chillerlan\Authenticator\Common\Base32;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\{DataProvider, Test};
use InvalidArgumentException, RuntimeException;
use function rawurlencode, sprintf, strlen;

abstract class AuthenticatorInterfaceTestAbstract extends TestCase{

	protected AuthenticatorOptions   $options;
	protected AuthenticatorInterface $authenticatorInterface;

	protected const rawsecret = '12345678901234567890';
	protected const secret    = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

	protected const label     = 'some test-label';
	protected const issuer    = 'chillerlan.net';

	abstract protected function getInstance(AuthenticatorOptions $options):AuthenticatorInterface;

	protected function setUp():void{
		$this->options                = new AuthenticatorOptions;
		$this->authenticatorInterface = $this->getInstance($this->options);
	}

	#[Test]
	public function setGetSecret():void{
		$this->authenticatorInterface->setSecret($this::secret);

		$secret = $this->authenticatorInterface->getSecret();

		$this::assertSame($this::secret, $secret);
		$this::assertSame($this::rawsecret, Base32::decode($secret));
	}

	#[Test]
	public function setEmptySecretException():void{
		$this->expectException(InvalidArgumentException::class);
		$this->expectExceptionMessage('The given secret string is empty');

		$this->authenticatorInterface->setSecret('');
	}

	#[Test]
	public function setInvalidSecretException():void{
		$this->expectException(InvalidArgumentException::class);

		$this->authenticatorInterface->setSecret('This_is_an_invalid_secret_phrase!');
	}

	#[Test]
	public function getSecretException():void{
		$this->expectException(RuntimeException::class);
		$this->expectExceptionMessage('No secret set');

		$this->authenticatorInterface->getSecret();
	}

	#[Test]
	public function createSecretDefaultLength():void{
		$this::assertSame(
			$this->options->secret_length,
			strlen(Base32::decode($this->authenticatorInterface->createSecret())),
		);
	}

	#[Test]
	public function createSecretWithLength():void{

		for($secretLength = 16; $secretLength <= 512; $secretLength += 8){
			$secret = Base32::decode($this->authenticatorInterface->createSecret($secretLength));

			$this::assertSame($secretLength, strlen($secret));
		}

	}

	#[Test]
	public function createSecretCheckCharacterSet():void{
		$secret = $this->authenticatorInterface->createSecret(32);

		$this::assertMatchesRegularExpression('/^['.Base32::CHARSET.']+$/', $secret);
	}

	#[Test]
	public function createSecretException():void{
		$this->expectException(InvalidArgumentException::class);
		$this->expectExceptionMessage('Invalid secret length');

		$this->authenticatorInterface->createSecret(10);
	}

	#[Test]
	public function getHMACWithoutSecretException():void{
		$this->expectException(RuntimeException::class);
		$this->expectExceptionMessage('No secret given');

		$this->authenticatorInterface->getHMAC(69);
	}

	// https://github.com/PHPGangsta/GoogleAuthenticator/pull/25
	#[Test]
	public function verifyCodeWithLeadingZero():void{
		$this->authenticatorInterface->setSecret($this::secret);

		$code = $this->authenticatorInterface->code();

		$this::assertTrue($this->authenticatorInterface->verify($code));
		$this::assertFalse($this->authenticatorInterface->verify('0'.$code));
	}

	// coverage
	#[Test]
	public function getServertime():void{
		$this->options->useLocalTime = false;

		$servertime = $this->authenticatorInterface->getServerTime();
		$this::assertMatchesRegularExpression('/^\d+$/', (string)$servertime);

		$this->options->forceTimeRefresh = false;

		$servertime = $this->authenticatorInterface->getServerTime();
		$this::assertMatchesRegularExpression('/^\d+$/', (string)$servertime);
	}

	abstract public static function uriSettingsProvider():array;

	/**
	 * @param array<string, mixed> $options
	 */
	#[Test]
	#[DataProvider('uriSettingsProvider')]
	public function getUri(array $options, string $expected):void{

		$this->authenticatorInterface
			->setOptions($options)
			->setSecret(self::secret)
		;

		$this::assertSame(
			sprintf(
				'otpauth://%s/%s?secret=%s&issuer=%s%s',
				$this->authenticatorInterface::MODE,
				rawurlencode(self::label),
				self::secret,
				rawurlencode(self::issuer),
				$expected,
			),
			$this->authenticatorInterface->getUri(self::label, self::issuer, 42),
		);

	}

}
