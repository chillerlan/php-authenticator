# chillerlan/php-authenticator

A generator for counter based ([RFC 4226](https://tools.ietf.org/html/rfc4226)) and time based ([RFC 6238](https://tools.ietf.org/html/rfc6238)) one time passwords (OTP). (a.k.a. Yet Another Google Authenticator Implementation!)

[![License][license-badge]][license]
[![GitHub actions workflow][gh-action-badge]][gh-action]
[![Coverage][coverage-badge]][coverage]
[![Codacy][codacy-badge]][codacy]

[license-badge]: https://img.shields.io/github/license/chillerlan/php-authenticator.svg
[license]: https://github.com/chillerlan/php-authenticator/blob/v5.x/LICENSE
[gh-action-badge]: https://img.shields.io/github/actions/workflow/status/chillerlan/php-authenticator/ci.yml?branch=v5.x&logo=github&logoColor=fff
[gh-action]: https://github.com/chillerlan/php-authenticator/actions?query=branch%3Av5.x
[coverage-badge]: https://img.shields.io/codecov/c/gh/chillerlan/php-authenticator/v5.x?logo=codecov&logoColor=fff
[coverage]: https://app.codecov.io/github/chillerlan/php-authenticator/tree/v5.x
[codacy-badge]: https://img.shields.io/codacy/grade/a2793225b448495c9659f27f7f52380a/v5.x?logo=codacy&logoColor=fff
[codacy]: https://www.codacy.com/gh/chillerlan/php-authenticator/dashboard?branch=v5.x

# Documentation
## Requirements
- PHP 8.2+
  - [`ext-curl`](https://www.php.net/manual/book.curl) for Steam Guard server time synchronization
  - [`ext-sodium`](https://www.php.net/manual/book.sodium) for constant time implementations of base64 encode/decode and hex2bin/bin2hex
    ([`paragonie/constant_time_encoding`](https://github.com/paragonie/constant_time_encoding) is used as fallback)

## Installation
**requires [composer](https://getcomposer.org)**

via terminal: `composer require chillerlan/php-authenticator`

**composer.json**
```json
{
	"require": {
		"php": "^8.2",
		"chillerlan/php-authenticator": "dev-v5.x"
	}
}
```
Note: replace `dev-main` with a [version constraint](https://getcomposer.org/doc/articles/versions.md#writing-version-constraints), e.g. `^5.0` - see [releases](https://github.com/chillerlan/php-authenticator/releases) for valid versions

Profit!

## Usage
### Create a secret
The secret is usually being created once during the activation process in a user control panel.
So all you need to do there is to display it to the user in a convenient way -
as a text string and QR code for example - and save it somewhere with the user data.
```php
use chillerlan\Authenticator\{Authenticator, AuthenticatorOptions};

$options = new AuthenticatorOptions;
$options->secret_length = 32;

$authenticator = new Authenticator($options);
// create a secret (stored somewhere in a *safe* place on the server. safe... hahaha jk)
$secret = $authenticator->createSecret();
// you can also specify the length of the secret key, which overrides the options setting
$secret = $authenticator->createSecret(20);
// set an existing secret
$authenticator->setSecret($secret);
```

A secret created with `Authenticator::createSecret()` will also be stored internally,
so that you don't need to provide the secret you just created on follow-up operations with the current instance.

### Verify a one time code
Now during the login process - after the user has successfully entered their credentials - you would
ask them for a one time code to check it against the secret from your user database.

```php
// verify the code
if($authenticator->verify($otp)){
	// that's it - 2FA has never been easier! :D
}
```

#### time based (TOTP)
Verify adjacent codes
```php
// try the first adjacent
$authenticator->verify($otp, time() - $options->period); // -> true
// try the second adjacent, default is 1
$authenticator->verify($otp, time() + 2 * $options->period); // -> false
// allow 2 adjacent codes
$options->adjacent = 2;
$authenticator->verify($otp, time() + 2 * $options->period); // -> true
```

#### counter based (HOTP)
```php
// switch mode to HOTP
$options->mode = AuthenticatorInterface::HOTP;
// user sends the OTP for code #42, which is equivalent to
$otp = $authenticator->code(42); // -> 123456
// verify [123456, 42]
$authenticator->verify($otp, $counterValueFromUserDatabase) // -> true
```

### URI creation
In order to display a QR code for a mobile authenticator you'll need an `otpauth://` URI, which can be created using the following method.
- `$label` should be something that identifies the account to which the secret belongs
- `$issuer` is the name of your website or company for example, so that the user is able to identify multiple accounts.
```php
$uri = $authenticator->getUri($label, $issuer);

// -> otpauth://totp/my%20label?secret=NKSOQG7UKKID4IXW&issuer=chillerlan.net&digits=6&period=30&algorithm=SHA1
```

#### Notes
Keep in mind that several URI settings are not (yet) recognized by all authenticators. Check [the Google Authenticator wiki](https://github.com/google/google-authenticator/wiki/Key-Uri-Format#parameters) for more info.

```php
// code length, currently 6 or 8
$options->digits = 8;
// valid period between 15 and 60 seconds
$options->period = 45;
// set the HMAC hash algorithm
$options->algorithm = AuthenticatorInterface::ALGO_SHA512;
```

## API
### `Authenticator`
| method                                                                                      | return          | description                                                      |
|---------------------------------------------------------------------------------------------|-----------------|------------------------------------------------------------------|
| `__construct(SettingsContainerInterface $options = null, string $secret = null)`            | -               |                                                                  |
| `setOptions(SettingsContainerInterface $options)`                                           | `Authenticator` | called internally by `__construct()`                             |
| `setSecret(string $secret)`                                                                 | `Authenticator` | called internally by `__construct()`                             |
| `getSecret()`                                                                               | `string`        |                                                                  |
| `createSecret(int $length = null)`                                                          | `string`        | `$length` overrides `AuthenticatorOptions` setting               |
| `code(int $data = null)`                                                                    | `string`        | `$data` may be a UNIX timestamp (TOTP) or a counter value (HOTP) |
| `verify(string $otp, int $data = null)`                                                     | `bool`          | for `$data` see `Authenticator::code()`                          |
| `getUri(string $label, string $issuer, int $hotpCounter = null, bool $omitSettings = null)` | `string`        |                                                                  |

### `AuthenticatorOptions`
#### Properties
| property            | type     | default | allowed                                | description                                                                     |
|---------------------|----------|---------|----------------------------------------|---------------------------------------------------------------------------------|
| `$digits`           | `int`    | 6       | 6 or 8                                 | auth code length                                                                |
| `$period`           | `int`    | 30      | 15 - 60                                | validation period (seconds)                                                     |
| `$secret_length`    | `int`    | 20      | &gt;= 16                               | length of the secret phrase (bytes, unencoded binary)                           |
| `$algorithm`        | `string` | `SHA1`  | `SHA1`, `SHA256` or `SHA512`           | HMAC hash algorithm, see `AuthenticatorInterface::HASH_ALGOS`                   |
| `$mode`             | `string` | `totp`  | `totp`, `hotp`, `battlenet` or `steam` | authenticator mode: time- or counter based, see `AuthenticatorInterface::MODES` |
| `$adjacent`         | `int`    | 1       | &gt;= 0                                | number of allowed adjacent codes                                                |
| `$time_offset`      | `int`    | 0       | *                                      | fixed time offset that will be added to the current time value                  |
| `$useLocalTime`     | `bool`   | true    | *                                      | whether to use local time or request server time                                |
| `$forceTimeRefresh` | `bool`   | false   | *                                      | whether to force refreshing server time on each call                            |

### `AuthenticatorInterface`
#### Methods
| method                                            | return                   | description |
|---------------------------------------------------|--------------------------|-------------|
| `setOptions(SettingsContainerInterface $options)` | `AuthenticatorInterface` |             |
| `setSecret(string $encodedSecret)`                | `AuthenticatorInterface` |             |
| `getSecret()`                                     | `string`                 |             |
| `createSecret(int $length = null)`                | `string`                 |             |
| `getServertime()`                                 | `int`                    |             |
| `getCounter(int $data = null)`                    | `int`                    | internal    |
| `getHMAC(int $counter)`                           | `string`                 | internal    |
| `getCode(string $hmac)`                           | `int`                    | internal    |
| `getOTP(int $code)`                               | `string`                 | internal    |
| `code(int $data = null)`                          | `string`                 |             |
| `verify(string $otp, int $data = null)`           | `bool`                   |             |

#### Constants
| constant      | type     | description                       |
|---------------|----------|-----------------------------------|
| `TOTP`        | `string` |                                   |
| `HOTP`        | `string` |                                   |
| `STEAM_GUARD` | `string` |                                   |
| `ALGO_SHA1`   | `string` |                                   |
| `ALGO_SHA256` | `string` |                                   |
| `ALGO_SHA512` | `string` |                                   |
| `MODES`       | `array`  | map of mode -> classname          |
| `HASH_ALGOS`  | `array`  | list of available hash algorithms |

<p align="center">
  <a href="https://twofactorauth.org">
    <img alt="2FA ALL THE THINGS!" src="https://raw.githubusercontent.com/chillerlan/php-authenticator/v5.x/.github/images/2fa-all-the-things.jpg">
  </a>
</p>
