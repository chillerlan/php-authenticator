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

require_once '../vendor/autoload.php';

$auth = new \chillerlan\Authenticator\Authenticator;

// create a secret
$secret = $auth->createSecret();

$auth
	// switch mode to HOTP
	->setMode('hotp')
	// change the code length
	->setDigits(8)
	// set the HMAC hash algo
	->setAlgorithm('sha256')
	// Authenticator::createSecret() stores the most recent created secret,
	// so you'll only need to call this when using existing secrets
	->setSecret($secret)
;

// get a one time code
$code = $auth->code(42);

// verify the code
// the internal counter will be increased by 1 on a successful verify
var_dump($auth->getCounter()); // -> 42
var_dump($auth->verify($code)); // -> true
var_dump($auth->getCounter()); // -> 43

var_dump($auth->verify($code, $auth->getCounter())); // -> true
var_dump($auth->getCounter()); // -> 44

$code = $auth->code(10);
// 1 adjacent allowed by default
var_dump($auth->verify($code, $auth->getCounter() + 2)); // -> false
// allow 2 adjacent codes
var_dump($auth->verify($code, $auth->getCounter() + 2, 2)); // -> true
var_dump($auth->getCounter()); // -> 13

// create an URI for use in e.g. QR codes
// -> otpauth://hotp/test?secret=EON2EEVRZSIUDZ3Z6N3NN264XQ&issuer=example.com&digits=8&counter=2&algorithm=SHA256
var_dump($auth->getUri('test', 'example.com'));
