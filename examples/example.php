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

// change the code length
Authenticator::setDigits(8);

// set validation period (seconds)
Authenticator::setPeriod(45);

// create a secret
$secret = Authenticator::createSecret();

// get a one time code
$code = Authenticator::getCode($secret);

// create an URI for use in e.g. QR codes
$label = 'test';
$issuer = 'chillerlan.net';
Authenticator::getUri($secret, $label, $issuer);
Authenticator::getGoogleQr($secret, $label, $issuer);

// verify the code
Authenticator::verifyCode($code, $secret);
