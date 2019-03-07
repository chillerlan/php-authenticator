<?php
/**
 * TOTP example
 *
 * @filesource   totp.php
 * @created      23.12.2017
 * @author       Smiley <smiley@chillerlan.net>
 * @copyright    2017 Smiley
 * @license      MIT
 */

use chillerlan\Authenticator\{Authenticator, AuthenticatorOptions};

require_once '../vendor/autoload.php';

$options = new AuthenticatorOptions([
	// switch mode to TOTP (default)
	'mode' => 'totp',
	// change the code length
	'digits' => 8,
	// set validation period (seconds)
	'period' => 60,
	// set the HMAC hash algo
	'algorithm' => 'sha512',
]);

$auth = new Authenticator($options);

// create a secret
// Authenticator::createSecret() stores the most recent created secret,
// so you'll only need to call this when using existing secrets
$secret = $auth->createSecret();

// get a one time code
$code = $auth->code();

// verify the current code
var_dump($auth->verify($code)); // -> true
// previous code
var_dump($auth->verify($code, time() - $options->period)); // -> true
// 2nd adjacent is invalid
var_dump($auth->verify($code, time() + 2 * $options->period)); // -> false
// allow 2 adjacent codes
$options->adjacent = 2;
var_dump($auth->setOptions($options)->verify($code, time() + 2 * $options->period, 2)); // -> true

// create an URI for use in e.g. QR codes
// -> otpauth://totp/test?secret=TPJNDLHMPOFXBWPSXYBUZBIHUI&issuer=example.com&digits=8&period=60&algorithm=SHA512
var_dump($auth->getUri('test', 'example.com'));
