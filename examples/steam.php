<?php
/**
 * Steam Guard example
 *
 * @created      23.12.2017
 * @author       Smiley <smiley@chillerlan.net>
 * @copyright    2017 Smiley
 * @license      MIT
 */
declare(strict_types=1);

use chillerlan\Authenticator\{Authenticator, AuthenticatorOptions};
use chillerlan\Authenticator\Authenticators\AuthenticatorInterface;

require_once '../vendor/autoload.php';

$options = new AuthenticatorOptions([
	// switch mode to STEAM_GUARD
	'mode' => AuthenticatorInterface::STEAM_GUARD,
]);

$auth = new Authenticator($options);

// set a secret (Steam Guard secrets are base64 encoded)
$secret = $auth->setSecret(base64_encode('secret'));

// get a one time code
$code = $auth->code();
var_dump($code);
// verify the current code
var_dump($auth->verify($code)); // -> true
// previous code
var_dump($auth->verify($code, (time() - $options->period))); // -> true
// 2nd adjacent is invalid
var_dump($auth->verify($code, (time() + 2 * $options->period))); // -> false
// allow 2 adjacent codes
$options->adjacent = 2;
var_dump($auth->verify($code, (time() + 2 * $options->period))); // -> true
