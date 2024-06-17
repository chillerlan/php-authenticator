<?php
/**
 * Class AuthenticatorOptions
 *
 * @created      07.03.2019
 * @author       smiley <smiley@chillerlan.net>
 * @copyright    2019 smiley
 * @license      MIT
 */
declare(strict_types=1);

namespace chillerlan\Authenticator;

use chillerlan\Settings\SettingsContainerAbstract;

/**
 *
 */
class AuthenticatorOptions extends SettingsContainerAbstract{
	use AuthenticatorOptionsTrait;
}
