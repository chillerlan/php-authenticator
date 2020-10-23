<?php
/**
 *
 * @filesource   AuthenticatorTest.php
 * @created      06.12.2015
 * @author       Smiley <smiley@chillerlan.net>
 * @copyright    2015 Smiley
 * @license      MIT
 */

namespace chillerlan\AuthenticatorTest;

use chillerlan\Authenticator\{Authenticator, AuthenticatorException, AuthenticatorOptions, Base32};
use PHPUnit\Framework\TestCase;

use function sprintf, str_pad, strlen, time;

use const STR_PAD_RIGHT;

class AuthenticatorTest extends TestCase{

	protected Authenticator        $authenticator;
	protected AuthenticatorOptions $options;
	protected string               $secret = 'SECRETTEST234567';

	protected function setUp():void{
		$this->options       = new AuthenticatorOptions;
		$this->authenticator = new Authenticator($this->options);
	}

	public function testCreateSecretDefaultLength():void{
		$secret = (new Base32)->toString($this->authenticator->createSecret());

		$this->assertSame($this->options->secret_length, strlen($secret));
	}

	public function testCreateSecretWithLength():void{

		for($secretLength = 16; $secretLength <= 512; $secretLength += 8){
			$secret = (new Base32)->toString($this->authenticator->createSecret($secretLength));

			$this->assertSame($secretLength, strlen($secret));
		}

	}

	public function testCreateSecretCheckCharacterSet():void{
		$this->options->secret_length = 32; // coverage

		$secret = $this->authenticator->setOptions($this->options)->createSecret();

		$this->assertMatchesRegularExpression('/^['.Base32::RFC3548.']+$/', $secret);
	}

	public function testCreateSecretException():void{
		$this->expectException(AuthenticatorException::class);
		$this->expectExceptionMessage('Invalid secret length');

		$this->authenticator->createSecret(10);
	}

	public function testSetGetSecret():void{
		$this->authenticator = new Authenticator($this->options, $this->secret);

		$this->assertSame($this->secret, $this->authenticator->getSecret());
	}

	public function testGetSecretException():void{
		$this->expectException(AuthenticatorException::class);
		$this->expectExceptionMessage('No secret set');

		$this->authenticator->getSecret();
	}

	public function totpCodeProvider():array{
		// time, code (unverified values for $this->secret)
		return [
			[         0, '730741'],
			[1385909245, '040137'],
			[1378934578, '341779'],
			[1449438863, '889844'],
		];
	}

	/**
	 * coverage
	 *
	 * @dataProvider totpCodeProvider
	 */
	public function testGetCodeTOTP(int $timestamp, string $code):void{
		$this->assertTrue($this->authenticator->setSecret($this->secret)->verify($code, $timestamp));
	}

	public function hotpCodeProvider():array{
		// counter, code (unverified values for $this->secret)
		return [
			[  0, '730741'],
			[  1, '219808'],
			[ 42, '803961'],
			[253, '403837'],
			[254, '442560'],
			[255, '606507'],
			[256, '918691'],
		];
	}

	/**
	 * coverage
	 *
	 * @dataProvider hotpCodeProvider
	 */
	public function testGetCodeHOTP(int $counter, string $code):void{
		$this->options->mode = 'hotp';
		$this->authenticator->setOptions($this->options);

		$this->assertTrue($this->authenticator->setSecret($this->secret)->verify($code, $counter));
	}

	public function testGetCodeException():void{
		$this->expectException(AuthenticatorException::class);
		$this->expectExceptionMessage('Invalid secret phrase');

		$this->authenticator = (new Authenticator($this->options, 'This-is-an-invalid-secret-phrase!'));
	}

	public function testVerifyCode():void{
		$this->assertTrue($this->authenticator->verify($this->authenticator->code()));
		$this->assertFalse($this->authenticator->verify('123456'));

		$a2 = clone $this->authenticator;
		$a2->setSecret($this->secret);

		$this->assertFalse($this->authenticator->verify($a2->code()));
	}

	public function testVerifyCodeWithTimeslice():void{
		$code      = $this->authenticator->code();
		$timestamp = time();

		// first adjacent code (default value)
		$this->assertTrue($this->authenticator->verify($code, $timestamp - 1 * $this->options->period));
		$this->assertFalse($this->authenticator->verify($code, $timestamp - 2 * $this->options->period));
	}

	public function testVerifyCodeWithTimesliceAndAdjacent():void{
		$code      = $this->authenticator->code();
		$timestamp = time();
		$adjacent  = 100;

		for($i = 0; $i <= $adjacent + 1; $i++){
			$this->options->adjacent = $adjacent;

			$verify = $this->authenticator
				->setOptions($this->options)
				->verify($code, $timestamp - $i * $this->options->period)
			;

			$i <= $adjacent
				? $this->assertTrue($verify)
				: $this->assertFalse($verify);
		}

	}

	// https://github.com/PHPGangsta/GoogleAuthenticator/pull/25
	public function testVerifyCodeWithLeadingZero():void{
		$code = $this->authenticator->code();

		$this->assertTrue($this->authenticator->verify($code));
		$this->assertFalse($this->authenticator->verify('0'.$code));
	}

	public function testGetUri():void{
		$label  = 'some test-label';
		$issuer = 'example.com';

		$expected = sprintf(
			'otpauth://%%s/%s?secret=%s&issuer=%s&digits=%%s&algorithm=%%s',
			'some%%20test-label', // rawurlencoded & sprintf-escaped
			$this->authenticator->createSecret(16),
			$issuer
		);

		$this->assertSame(sprintf($expected.'&period=%s', 'totp', 6, 'SHA1', 30), $this->authenticator->getUri($label, $issuer));

		$this->options->digits = 8;
		$this->authenticator->setOptions($this->options);
		$this->assertSame(sprintf($expected.'&period=%s', 'totp', 8, 'SHA1', 30), $this->authenticator->getUri($label, $issuer));

		$this->options->period = 45;
		$this->authenticator->setOptions($this->options);
		$this->assertSame(sprintf($expected.'&period=%s', 'totp', 8, 'SHA1', 45), $this->authenticator->getUri($label, $issuer));

		$this->options->mode = 'hotp';
		$this->authenticator->setOptions($this->options);
		$this->assertSame(sprintf($expected.'&counter=%s', 'hotp', 8, 'SHA1', 42), $this->authenticator->getUri($label, $issuer, 42));

		$this->options->algorithm = 'SHA512';
		$this->authenticator->setOptions($this->options);
		$this->assertSame(sprintf($expected, 'hotp', 8, 'SHA512'), $this->authenticator->getUri($label, $issuer));
	}

	public function hotpVectors():array{
		return [
			// https://tools.ietf.org/html/rfc4226#page-32
			[0, '755224'],
			[1, '287082'],
			[2, '359152'],
			[3, '969429'],
			[4, '338314'],
			[5, '254676'],
			[6, '287922'],
			[7, '162583'],
			[8, '399871'],
			[9, '520489'],
		];
	}

	/**
	 * @dataProvider hotpVectors
	 * @link         https://github.com/winauth/winauth/issues/449#issuecomment-353670105
	 */
	public function testHOTP(int $counter, string $code):void{
		$this->options->mode = 'hotp';

		$secret = (new Base32)->fromString('12345678901234567890');

		$this->assertSame('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', $secret);

		$this->authenticator
			->setOptions($this->options)
			->setSecret($secret)
		;

		$this->assertTrue($this->authenticator->verify($code, $counter));
	}

	public function totpVectors():array{
		return [
			// https://tools.ietf.org/html/rfc6238#page-14
			[         59, '94287082', 'sha1'  ],
			[ 1111111109, '07081804', 'sha1'  ],
			[ 1111111111, '14050471', 'sha1'  ],
			[ 1234567890, '89005924', 'sha1'  ],
			[ 2000000000, '69279037', 'sha1'  ],
			[20000000000, '65353130', 'sha1'  ],
			[         59, '46119246', 'sha256'],
			[ 1111111109, '68084774', 'sha256'],
			[ 1111111111, '67062674', 'sha256'],
			[ 1234567890, '91819424', 'sha256'],
			[ 2000000000, '90698825', 'sha256'],
			[20000000000, '77737706', 'sha256'],
			[         59, '90693936', 'sha512'],
			[ 1111111109, '25091201', 'sha512'],
			[ 1111111111, '99943326', 'sha512'],
			[ 1234567890, '93441116', 'sha512'],
			[ 2000000000, '38618901', 'sha512'],
			[20000000000, '47863826', 'sha512'],
		];
	}

	/**
	 * @dataProvider totpVectors
	 */
	public function testTOTP(int $timestamp, string $code, string $algorithm):void{
		$s = '12345678901234567890';

		$secret = [
			'sha1'   => $s,
			'sha256' => str_pad($s, 32, $s, STR_PAD_RIGHT),
			'sha512' => str_pad($s, 64, $s, STR_PAD_RIGHT),
		][$algorithm];

		$this->options->digits    = 8;
		$this->options->algorithm = $algorithm;

		$this->authenticator
			->setOptions($this->options)
			->setSecret((new Base32)->fromString($secret))
		;

		$this->assertFalse($this->authenticator->verify($code, $timestamp - 60));
		$this->assertTrue($this->authenticator->verify($code, $timestamp - 30));
		$this->assertTrue($this->authenticator->verify($code, $timestamp));
		$this->assertTrue($this->authenticator->verify($code, $timestamp + 30));
		$this->assertFalse($this->authenticator->verify($code, $timestamp + 60));
	}

}
