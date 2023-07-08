<?php
/**
 * TOTP example
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
	// switch mode to TOTP (default)
	'mode'      => AuthenticatorInterface::TOTP,
	// change the code length
	'digits'    => 8,
	// set validation period (seconds)
	'period'    => 60,
	// set the HMAC hash algo
	'algorithm' => AuthenticatorInterface::ALGO_SHA512,
];

$auth = new Authenticator($options);

// create a secret
$secret = $auth->createSecret();

// Authenticator::createSecret() stores the most recent created secret,
// so you'll only need to call this when using existing secrets
$auth->setSecret($secret);
// user sends a one time code
$code = $auth->code();
var_dump($code);
// verify the code
var_dump($auth->verify($code)); // -> true
// verify against the previous time slice
var_dump($auth->verify($code, (time() - $options['period']))); // -> true
// 2 stepos ahead (1 is default)
var_dump($auth->verify($code, (time() + 2 * $options['period']))); // -> false
// set adjacent codes to 2 and try again
$auth->setOptions(['adjacent' => 2]);
var_dump($auth->verify($code, (time() + 2 * $options['period']))); // -> true

// create an URI for use in e.g. QR codes
// -> otpauth://totp/test?secret=JQUZJ44H6M3SATXIJRKTK64VQMIU73JN&issuer=example.com&digits=8&algorithm=SHA512&period=60
var_dump($auth->getUri('test', 'example.com'));
// omit additional settings
// -> otpauth://totp/test?secret=FPBN5IDIAYIBUVRCNIKHCVJKAXL5SK4G&issuer=example.com
var_dump($auth->getUri('test', 'example.com', null, true));
