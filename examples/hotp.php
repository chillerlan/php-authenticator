<?php
/**
 * HOTP example
 *
 * @filesource   hotp.php
 * @created      23.12.2017
 * @author       Smiley <smiley@chillerlan.net>
 * @copyright    2017 Smiley
 * @license      MIT
 */

use chillerlan\Authenticator\Authenticator;
use chillerlan\Authenticator\AuthenticatorOptions;

require_once '../vendor/autoload.php';

$options = new AuthenticatorOptions([
	// switch mode to TOTP (default)
	'mode' => 'hotp',
	// change the code length
	'digits' => 8,
	// set validation period (seconds)
	'period' => 60,
	// set the HMAC hash algo
	'algorithm' => 'sha256',
]);

$auth = new Authenticator($options);

// create a secret
// Authenticator::createSecret() stores the most recent created secret,
// so you'll only need to call this when using existing secrets
$secret = $auth->createSecret();

// get a one time code
$code = $auth->code(42);

// verify the code
var_dump($auth->verify($code, 42)); // -> true

// create an URI for use in e.g. QR codes
// -> otpauth://hotp/test?secret=EON2EEVRZSIUDZ3Z6N3NN264XQ&issuer=example.com&digits=8&counter=2&algorithm=SHA256&counter=42
var_dump($auth->getUri('test', 'example.com', 42));
