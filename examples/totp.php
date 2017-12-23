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

require_once '../vendor/autoload.php';

$auth = new \chillerlan\Authenticator\Authenticator;

// create a secret
$secret = $auth->createSecret();

$auth
	// switch mode to TOTP (default)
	->setMode('totp')
	// change the code length
	->setDigits(8)
	// set validation period (seconds)
	->setPeriod(60)
	// set the HMAC hash algo
	->setAlgorithm('sha512')
	// Authenticator::createSecret() stores the most recent created secret,
	// so you'll only need to call this when using existing secrets
	->setSecret($secret)
;

// get a one time code
$code = $auth->code();

// verify the code
var_dump($auth->verify($code)); // -> true
var_dump($auth->verify($code, time() - $auth->getPeriod())); // -> true
var_dump($auth->verify($code, time() + 2 * $auth->getPeriod())); // -> false
var_dump($auth->verify($code, time() + 2 * $auth->getPeriod(), 2)); // -> true

// create an URI for use in e.g. QR codes
// -> otpauth://totp/test?secret=TPJNDLHMPOFXBWPSXYBUZBIHUI&issuer=example.com&digits=8&period=60&algorithm=SHA512
var_dump($auth->getUri('test', 'example.com'));
