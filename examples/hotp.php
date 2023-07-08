<?php
/**
 * HOTP example
 *
 * @created      23.12.2017
 * @author       Smiley <smiley@chillerlan.net>
 * @copyright    2017 Smiley
 * @license      MIT
 */

use chillerlan\Authenticator\Authenticator;
use chillerlan\Authenticator\Authenticators\AuthenticatorInterface;

require_once '../vendor/autoload.php';

$options = [
	// switch mode to HOTP
	'mode'      => AuthenticatorInterface::HOTP,
	// change the code length
	'digits'    => 8,
	// set the HMAC hash algo
	'algorithm' => AuthenticatorInterface::ALGO_SHA256,
];

$auth = new Authenticator($options);

// create a secret
$secret = $auth->createSecret();

// Authenticator::createSecret() stores the most recent created secret,
// so you'll only need to call this when using existing secrets
$auth->setSecret($secret);

// user sends a one time code for counter #42
$code = $auth->code(42);
var_dump($code);
// backend verifies the code with the internally stored counter value
var_dump($auth->verify($code, 42)); // -> true

// create an URI for use in e.g. QR codes
// -> otpauth://hotp/test?secret=XVSWWIXN4NMA3XNNDJ6XTFSLM3DILOTZ&issuer=example.com&digits=8&algorithm=SHA256&counter=42
var_dump($auth->getUri('test', 'example.com', 42));
// omit additional settings
// -> otpauth://hotp/test?secret=XVSWWIXN4NMA3XNNDJ6XTFSLM3DILOTZ&issuer=example.com
var_dump($auth->getUri('test', 'example.com', 42, true));
