<?php
/**
 * Class AuthenticatorTest
 *
 * @created      06.12.2015
 * @author       Smiley <smiley@chillerlan.net>
 * @copyright    2015 Smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\AuthenticatorTest;

use chillerlan\Authenticator\{Authenticator, AuthenticatorOptions};
use chillerlan\Authenticator\Authenticators\AuthenticatorInterface;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use function sprintf;

class AuthenticatorTest extends TestCase{

	protected const secret = 'SECRETTEST234567';
	protected const label  = 'some test-label';
	protected const issuer = 'chillerlan.net';

	protected Authenticator        $authenticator;
	protected AuthenticatorOptions $options;

	protected function setUp():void{
		$this->options       = new AuthenticatorOptions;
		$this->authenticator = new Authenticator($this->options);
	}

	public function testSetSecretViaConstruct():void{
		$this->authenticator = new Authenticator(secret: self::secret);

		$this::assertSame(self::secret, $this->authenticator->getSecret());
	}

	public function testGetUri():void{
		$this->authenticator->setSecret(self::secret);

		$label  = rawurlencode(self::label);
		$issuer = rawurlencode(self::issuer);

		$this->options->omitUriSettings = false;
		$this::assertSame(
			sprintf('otpauth://totp/%s?secret=%s&issuer=%s&digits=6&algorithm=SHA1&period=30', $label, self::secret, $issuer),
			$this->authenticator->getUri(self::label, self::issuer),
		);

		$this->options->digits = 8;
		$this::assertSame(
			sprintf('otpauth://totp/%s?secret=%s&issuer=%s&digits=8&algorithm=SHA1&period=30', $label, self::secret, $issuer),
			$this->authenticator->getUri(self::label, self::issuer),
		);

		$this->options->period = 45;
		$this::assertSame(
			sprintf('otpauth://totp/%s?secret=%s&issuer=%s&digits=8&algorithm=SHA1&period=45', $label, self::secret, $issuer),
			$this->authenticator->getUri(self::label, self::issuer),
		);

		$this->options->mode = AuthenticatorInterface::HOTP;
		// changing the mode resets the AuthenticatorInterface instance
		$this->authenticator
			->setOptions($this->options)
			->setSecret(self::secret);

		$this::assertSame(
			sprintf('otpauth://hotp/%s?secret=%s&issuer=%s&counter=42&digits=8&algorithm=SHA1', $label, self::secret, $issuer),
			$this->authenticator->getUri(self::label, self::issuer, 42),
		);

		$this->options->algorithm = AuthenticatorInterface::ALGO_SHA512;
		$this::assertSame(
			sprintf('otpauth://hotp/%s?secret=%s&issuer=%s&counter=0&digits=8&algorithm=SHA512', $label, self::secret, $issuer),
			$this->authenticator->getUri(self::label, self::issuer, 0),
		);

		// test omit settings
		$this::assertSame(
			sprintf('otpauth://%s/%s?secret=%s&issuer=%s&counter=42', 'hotp', $label, self::secret, $issuer),
			$this->authenticator->getUri(self::label, self::issuer, 42, true),
		);
	}

	public function testGetUriEmptyLabelException():void{
		$this->expectException(InvalidArgumentException::class);
		$this->expectExceptionMessage('$label and $issuer cannot be empty');

		$this->authenticator->getUri('  ', '');
	}

}
