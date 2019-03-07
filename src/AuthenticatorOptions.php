<?php
/**
 * Class AuthenticatorOptions
 *
 * @filesource   AuthenticatorOptions.php
 * @created      07.03.2019
 * @package      chillerlan\Authenticator
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2019 smiley
 * @license      MIT
 */

namespace chillerlan\Authenticator;

use chillerlan\Settings\SettingsContainerAbstract;

/**
 * @property int    $digits
 * @property int    $period
 * @property int    $secret_length
 * @property string $algorithm
 * @property string $mode
 * @property int    $adjacent
 */
class AuthenticatorOptions extends SettingsContainerAbstract{
	use AuthenticatorOptionsTrait;
}
