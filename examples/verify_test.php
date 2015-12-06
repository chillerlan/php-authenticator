<?php
/**
 * Google authenticator example
 *
 * @filesource   verify_test.php
 * @created      06.12.2015
 * @author       Smiley <smiley@chillerlan.net>
 * @copyright    2015 Smiley
 * @license      MIT
 */

require_once '../vendor/autoload.php';

use chillerlan\GoogleAuth\Authenticator;

$secret = Authenticator::createSecret();
$code = Authenticator::getCode($secret);

$timestamp = time();
$adjacent = 100;

var_dump([$secret, $code, $timestamp]);

for($i = 0; $i <= $adjacent+1; $i++){
	$t = $timestamp - $i * Authenticator::$period;
	$timeslice = floor($t / Authenticator::$period);

	print_r([
		$i,
		$t,
		$timeslice,
		(int)Authenticator::verifyCode($code, $secret, $timeslice, $adjacent),
	]);
}
