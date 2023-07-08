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

use chillerlan\Authenticator\Authenticator;
use chillerlan\Authenticator\Authenticators\AuthenticatorInterface;
use chillerlan\Authenticator\Common\Base32;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;
use RuntimeException;
use function strlen;
use function strtoupper;

/**
 *
 */
abstract class AuthenticatorInterfaceTestAbstract extends TestCase{

	/** @var \chillerlan\Authenticator\Authenticators\AuthenticatorInterface */
	protected $authenticatorInterface;

	const rawsecret = '12345678901234567890';
	const secret    = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

	abstract protected function getInstance();

	protected function setUp(){
		$this->authenticatorInterface = $this->getInstance();
	}

	protected function getAuthenticatorInterfaceProperty($property){
		$r = new ReflectionProperty($this->authenticatorInterface, $property);
		$r->setAccessible(true);

		return $r->getValue($this->authenticatorInterface);
	}

	public function testSetGetSecret(){
		$this->authenticatorInterface->setSecret($this::secret);

		$this::assertSame($this::secret, $this->authenticatorInterface->getSecret());
	}

	public function testSetEmptySecretException(){
		$this->expectException(InvalidArgumentException::class);
		$this->expectExceptionMessage('The given secret string is empty');

		$this->authenticatorInterface->setSecret('');
	}

	public function testSetInvalidSecretException(){
		$this->expectException(InvalidArgumentException::class);

		$this->authenticatorInterface->setSecret('This_is_an_invalid_secret_phrase!');
	}

	public function testGetSecretException(){
		$this->expectException(RuntimeException::class);
		$this->expectExceptionMessage('No secret set');

		$this->authenticatorInterface->getSecret();
	}

	public function testCreateSecretDefaultLength(){
		$this::assertSame(
			Authenticator::DEFAULTS['secret_length'],
			strlen(Base32::decode($this->authenticatorInterface->createSecret()))
		);
	}

	public function testCreateSecretWithLength(){

		for($secretLength = 16; $secretLength <= 512; $secretLength += 8){
			$secret = Base32::decode($this->authenticatorInterface->createSecret($secretLength));

			$this::assertSame($secretLength, strlen($secret));
		}

	}

	public function testCreateSecretCheckCharacterSet(){
		$secret = $this->authenticatorInterface->createSecret(32);

		$this::assertRegExp('/^['.Base32::CHARSET.']+$/', $secret);
	}

	public function testCreateSecretException(){
		$this->expectException(InvalidArgumentException::class);
		$this->expectExceptionMessage('Invalid secret length');

		$this->authenticatorInterface->createSecret(10);
	}

	public function testGetHMACWithoutSecretException(){
		$this->expectException(RuntimeException::class);
		$this->expectExceptionMessage('No secret given');

		$this->authenticatorInterface->getHMAC(69);
	}

	// https://github.com/PHPGangsta/GoogleAuthenticator/pull/25
	public function testVerifyCodeWithLeadingZero(){
		$this->authenticatorInterface->setSecret($this::secret);

		$code = $this->authenticatorInterface->code();

		$this::assertTrue($this->authenticatorInterface->verify($code));
		$this::assertFalse($this->authenticatorInterface->verify('0'.$code));
	}

	public function testSetAlgorithm(){
		foreach(AuthenticatorInterface::HASH_ALGOS as $algo){
			$this->authenticatorInterface->setOptions(['algorithm' => $algo]);
			$this::assertSame(strtoupper($algo), $this->getAuthenticatorInterfaceProperty('algorithm'));
		}
	}

	public function testSetAlgorithmException(){
		$this->expectException(InvalidArgumentException::class);
		$this->expectExceptionMessage('Invalid algorithm');

		$this->authenticatorInterface->setOptions(['algorithm' => 'florps']);
	}

	public function testSetDigits(){
		foreach([6, 8] as $digits){
			$this->authenticatorInterface->setOptions(['digits' => $digits]);
			$this::assertSame($digits, $this->getAuthenticatorInterfaceProperty('digits'));
		}
	}

	public function testSetDigitsException(){
		$this->expectException(InvalidArgumentException::class);
		$this->expectExceptionMessage('Invalid code length');

		$this->authenticatorInterface->setOptions(['digits' => 9]);
	}

	public function testSetPeriod(){
		for($period = 15; $period <= 60; $period++){
			$this->authenticatorInterface->setOptions(['period' => $period]);
			$this::assertSame($period, $this->getAuthenticatorInterfaceProperty('period'));
		}
	}

	public function testSetPeriodException(){
		$this->expectException(InvalidArgumentException::class);
		$this->expectExceptionMessage('Invalid period');

		$this->authenticatorInterface->setOptions(['period' => 1]);
	}

	public function testSetSecretLength(){
		for($secret_length = 16; $secret_length <= 1024; $secret_length += 16){
			$this->authenticatorInterface->setOptions(['secret_length' => $secret_length]);
			$this::assertSame($secret_length, $this->getAuthenticatorInterfaceProperty('secret_length'));
		}
	}

	public function testSetSecretLengthException(){
		$this->expectException(InvalidArgumentException::class);
		$this->expectExceptionMessage('Invalid secret length');

		$this->authenticatorInterface->setOptions(['secret_length' => 69420]);
	}

	public function testSetAdjacentException(){
		$this->expectException(InvalidArgumentException::class);
		$this->expectExceptionMessage('Invalid adjacent value');

		$this->authenticatorInterface->setOptions(['adjacent' => -666]);
	}

}
