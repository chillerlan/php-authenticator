<?php
/**
 * Battle.net example
 *
 * @created      28.06.2023
 * @author       Smiley <smiley@chillerlan.net>
 * @copyright    2023 Smiley
 * @license      MIT
 */

use chillerlan\Authenticator\{Authenticator, AuthenticatorOptions, Authenticators\BattleNet};
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
var_dump($auth->verify($code, time() - $options->period)); // -> true
// 2nd adjacent is invalid
var_dump($auth->verify($code, time() + 2 * $options->period)); // -> false
// allow 2 adjacent codes
$options->adjacent = 2;
var_dump($auth->verify($code, time() + 2 * $options->period)); // -> true

// request a new authenticator from the Battle.net API
// this requires the BattleNet class to be invoked directly as we're using non-interface methods for this
$auth = new BattleNet;
$data = $auth->createAuthenticator('EU');
// the serial can be used to attach this authenticator to an existing Battle.net account
var_dump($data);
// it's also possible to retreive an authenticator secret from an existing serial and restore code, e.g. from WinAuth
$data = $auth->restoreSecret($data['serial'], $data['restore_code']);
var_dump($data);
