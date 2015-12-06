<?php
/**
 * Google authenticator example
 *
 * @filesource   example.php
 * @created      06.12.2015
 * @author       Smiley <smiley@chillerlan.net>
 * @copyright    2015 Smiley
 * @license      MIT
 */

require_once '../vendor/autoload.php';

use chillerlan\GoogleAuth\Authenticator;


$label = 'test';
$issuer = 'chillerlan.net';

// create a secret
$secret = Authenticator::createSecret();
var_dump($secret);

// get a one time code
$code = Authenticator::getCode($secret);

var_dump([
	// create an URI for use in e.g. QR codes
	Authenticator::getUri($secret, $label, $issuer),
	Authenticator::getGoogleQr($secret, $label, $issuer),
	$code,
	// verify the code
	Authenticator::verifyCode($code, $secret)
]);


// change the code length
Authenticator::setDigits(8);
$code = Authenticator::getCode($secret);

var_dump([
	Authenticator::getUri($secret, $label, $issuer),
	Authenticator::getGoogleQr($secret, $label, $issuer),
	$code,
	Authenticator::verifyCode($code, $secret)
]);
