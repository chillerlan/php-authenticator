<?php
/**
 * Battle.net example
 *
 * @created      28.06.2023
 * @author       Smiley <smiley@chillerlan.net>
 * @copyright    2023 Smiley
 * @license      MIT
 */

use chillerlan\Authenticator\{Authenticator, AuthenticatorOptions};
use chillerlan\Authenticator\Authenticators\AuthenticatorInterface;

require_once '../vendor/autoload.php';

$options = new AuthenticatorOptions([
	// switch mode to BATTLE_NET
	'mode' => AuthenticatorInterface::BATTLE_NET,
]);

$auth = new Authenticator($options);

// set a secret - Battle.net secrets come as hex strings (20 byte, 40 chars)
$secret = $auth->setSecret('3132333435363738393031323334353637383930');
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
