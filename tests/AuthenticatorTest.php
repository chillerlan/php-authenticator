<?php
/**
 * Class AuthenticatorTest
 *
 * @created      06.12.2015
 * @author       Smiley <smiley@chillerlan.net>
 * @copyright    2015 Smiley
 * @license      MIT
 */

namespace chillerlan\AuthenticatorTest;

use chillerlan\Authenticator\Authenticator;
use chillerlan\Authenticator\Authenticators\AuthenticatorInterface;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;
use function rawurlencode;
use function sprintf;

class AuthenticatorTest extends TestCase{

	const secret = 'SECRETTEST234567';
	const label  = 'some test-label';
	const issuer = 'chillerlan.net';

	/** @var \chillerlan\Authenticator\Authenticator */
	protected $authenticator;

	protected function setUp(){
		$this->authenticator = new Authenticator;
	}

	protected function getAuthenticatorProperty($property){
		$r = new ReflectionProperty($this->authenticator, $property);
		$r->setAccessible(true);

		return $r->getValue($this->authenticator);
	}

	public function testSetOptionsRemoveUnwantedKeys(){
		$this->authenticator->setOptions(['foo' => 'bar']);

		$this::assertArrayNotHasKey('foo', $this->getAuthenticatorProperty('options'));
	}

	public function testSetMode(){
		foreach(AuthenticatorInterface::MODES as $mode => $class){
			$this->authenticator->setOptions(['mode' => $mode]);

			$this::assertSame($mode, $this->getAuthenticatorProperty('mode'));
			$this::assertInstanceOf($class, $this->getAuthenticatorProperty('authenticator'));
		}
	}

	public function testSetModeException(){
		$this->expectException(InvalidArgumentException::class);
		$this->expectExceptionMessage('Invalid mode');

		$this->authenticator->setOptions(['mode' => 'florps']);
	}

	public function testSetSecretViaConstruct(){
		$this->authenticator = new Authenticator(null, self::secret);

		$this::assertSame(self::secret, $this->authenticator->getSecret());
	}

	public function testGetUri(){
		$this->authenticator->setSecret(self::secret);

		$label  = rawurlencode(self::label);
		$issuer = rawurlencode(self::issuer);

		$this::assertSame(
			sprintf('otpauth://totp/%s?secret=%s&issuer=%s&digits=6&algorithm=SHA1&period=30', $label, self::secret, $issuer),
			$this->authenticator->getUri(self::label, self::issuer)
		);

		$this->authenticator->setOptions(['digits' => 8]);
		$this::assertSame(
			sprintf('otpauth://totp/%s?secret=%s&issuer=%s&digits=8&algorithm=SHA1&period=30', $label, self::secret, $issuer),
			$this->authenticator->getUri(self::label, self::issuer)
		);

		$this->authenticator->setOptions(['period' => 45]);
		$this::assertSame(
			sprintf('otpauth://totp/%s?secret=%s&issuer=%s&digits=8&algorithm=SHA1&period=45', $label, self::secret, $issuer),
			$this->authenticator->getUri(self::label, self::issuer)
		);

		$this->authenticator
			->setOptions(['mode' => AuthenticatorInterface::HOTP])
			// changing the mode resets the AuthenticatorInterface instance
			->setSecret(self::secret);

		$this::assertSame(
			sprintf('otpauth://hotp/%s?secret=%s&issuer=%s&digits=8&algorithm=SHA1&counter=42', $label, self::secret, $issuer),
			$this->authenticator->getUri(self::label, self::issuer, 42)
		);

		$this->authenticator->setOptions(['algorithm' => AuthenticatorInterface::ALGO_SHA512]);
		$this::assertSame(
			sprintf('otpauth://hotp/%s?secret=%s&issuer=%s&digits=8&algorithm=SHA512', $label, self::secret, $issuer),
			$this->authenticator->getUri(self::label, self::issuer)
		);

		// test omit settings
		$this::assertSame(
			sprintf('otpauth://%s/%s?secret=%s&issuer=%s', 'hotp', $label, self::secret, $issuer),
			$this->authenticator->getUri(self::label, self::issuer, 42, true)
		);
	}

	public function testGetUriEmptyLabelException(){
		$this->expectException(InvalidArgumentException::class);
		$this->expectExceptionMessage('$label and $issuer cannot be empty');

		$this->authenticator->getUri('  ', '');
	}

}
