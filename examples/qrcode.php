<?php
/**
 *
 * @filesource   qrcode.php
 * @created      04.05.2019
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2019 smiley
 * @license      MIT
 */

use chillerlan\Authenticator\{Authenticator, AuthenticatorOptionsTrait};
use chillerlan\QRCode\{QRCode, QROptionsTrait};
use chillerlan\Settings\SettingsContainerAbstract;

require_once __DIR__.'/../vendor/autoload.php';

$options = [
	// authenticator
	'mode'          => 'totp',
	'secret_length' => 32,
	'algorithm'     => 'sha512',
	// qrcode
	'version'       => 7,
	'outputType'    => QRCode::OUTPUT_IMAGE_PNG,
	'eccLevel'      => QRCode::ECC_L,
	'scale'         => 5,
	'imageBase64'   => true,
];

$options = new class ($options) extends SettingsContainerAbstract{
	use AuthenticatorOptionsTrait, QROptionsTrait;
};

$authenticator = new Authenticator($options);

// store the secret with th user data
$secret = $authenticator->createSecret();

$uri = $authenticator->getUri('authenticator-test', 'issuer');

echo '<img src="'.(new QRCode($options))->render($uri).'" /><br/>'.$uri.'<br/>';
