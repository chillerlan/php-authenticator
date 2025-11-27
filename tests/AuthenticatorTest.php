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
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use InvalidArgumentException;

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

	#[Test]
	public function setSecretViaConstruct():void{
		$this->authenticator = new Authenticator(secret: self::secret);

		$this::assertSame(self::secret, $this->authenticator->getSecret());
	}

	#[Test]
	public function getUriEmptyLabelException():void{
		$this->expectException(InvalidArgumentException::class);
		$this->expectExceptionMessage('$label and $issuer cannot be empty');

		$this->authenticator->getUri('  ', '');
	}

}
