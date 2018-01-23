# chillerlan/php-authenticator

A generator for counter based ([RFC 4226](https://tools.ietf.org/html/rfc4226)) and time based ([RFC 6238](https://tools.ietf.org/html/rfc6238)) authentication codes. (a.k.a. Yet Another Google Authenticator Implementation!)

[![version][packagist-badge]][packagist]
[![license][license-badge]][license]
[![Travis][travis-badge]][travis]
[![Coverage][coverage-badge]][coverage]
[![Scrunitizer][scrutinizer-badge]][scrutinizer]
[![Downloads][downloads-badge]][downloads]
[![PayPal donate][donate-badge]][donate]

[packagist-badge]: https://img.shields.io/packagist/v/chillerlan/php-authenticator.svg?style=flat-square
[packagist]: https://packagist.org/packages/chillerlan/php-authenticator
[license-badge]: https://img.shields.io/github/license/chillerlan/php-authenticator.svg?style=flat-square
[license]: https://github.com/chillerlan/php-authenticator/blob/master/LICENSE
[travis-badge]: https://img.shields.io/travis/chillerlan/php-authenticator.svg?style=flat-square
[travis]: https://travis-ci.org/chillerlan/php-authenticator
[coverage-badge]: https://img.shields.io/codecov/c/github/chillerlan/php-authenticator.svg?style=flat-square
[coverage]: https://codecov.io/github/chillerlan/php-authenticator
[scrutinizer-badge]: https://img.shields.io/scrutinizer/g/chillerlan/php-authenticator.svg?style=flat-square
[scrutinizer]: https://scrutinizer-ci.com/g/chillerlan/php-authenticator
[downloads-badge]: https://img.shields.io/packagist/dt/chillerlan/php-authenticator.svg?style=flat-square
[downloads]: https://packagist.org/packages/chillerlan/php-authenticator/stats
[donate-badge]: https://img.shields.io/badge/donate-paypal-ff33aa.svg?style=flat-square
[donate]: https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=WLYUNAT9ZTJZ4

# Documentation
## Requirements
- PHP 7+
  - 64bit

## Installation
**requires [composer](https://getcomposer.org)**

*composer.json* (note: replace `dev-master` with a version boundary)
```json
{
	"require": {
		"php": ">=7.0.3",
		"chillerlan/php-qrcode": "dev-master"
	}
}
```

### Manual installation
Download the desired version of the package from [master](https://github.com/chillerlan/php-authenticator/archive/master.zip) or 
[release](https://github.com/chillerlan/php-authenticator/releases) and extract the contents to your project folder.  After that:
- run `composer install` to install the required dependencies and generate `/vendor/autoload.php`.
- if you use a custom autoloader, point the namespace `chillerlan\Authenticator` to the folder `src` of the package 

Profit!

## Usage
### Create a secret 
The secret is usually being created once during the activation process in a user control panel. 
So all you need to do there is to display it to the user in a convenient way - 
as a text string and QR code for example - and save it somewhere with the user data.
```php
$authenticator = new \chillerlan\Authenticator\Authenticator;

// create a secret (stored somewhere in a *safe* place on the server. safe... hahaha)
$secret = $authenticator->createSecret();

// you can also specify the length of the secret key
$secret = $authenticator->createSecret(20);

// set an existing secret
$authenticator->setSecret($secret);
```

A secret created with `Authenticator::createSecret()` will also be stored internally, so that you don't need to provide the one you just created on follow-up operations for the same secret.

### Verify a one time code
Now during the login process - after the user has successfully entered their credentials - you would 
ask them for a one time code to check it against the secret from your user database.

```php
// verify the code
if($authenticator->verify($code)){
	// that's it - 2FA has never been easier! :D
}
```

#### time based (TOTP)
Verify adjacent codes
```php
$p = $authenticator->getPeriod();

// try the first adjacent
$authenticator->verify($code, time() - $p); // -> true

// try the second adjacent, default is 1
$authenticator->verify($code, time() + 2 * $p); // -> false

// allow 2 adjacent codes
$authenticator->verify($code, time() + 2 * $p, 2); // -> true
```

Create a code for a UNIX timestamp
```php
// let's assume your server's timezone is an hour off and beyond your control
$timeslice = $authenticator->timeslice(time() - 3600);

// current code
$code = $authenticator->code($timeslice);

// adjacent codes
$prev = $authenticator->code($timeslice - 1);
$next = $authenticator->code($timeslice + 1);
```

#### counter based (HOTP)
```php
// switch mode to HOTP
$authenticator->setMode('hotp');

// user sends code #42, equivalent to
$code = $authenticator->code(42);

// try the first adjacent
$authenticator->verify($code, $counterValueFromUserDatabase + 1) // -> true
	
// the internal counter will be increased by 1 on a successful verify
$authenticator->getCounter(); // -> 43, save

// user sends following code (#43)
$authenticator->verify($nextCode, $counterValueFromUserDatabase); // -> true
$authenticator->getCounter(); // -> 44, save...
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
// code length, currently 6 through 8
$authenticator->setDigits(8);

// valid period between 10 and 60 seconds
$authenticator->setPeriod(45);

// set the HMAC hash algorithm
$authenticator->setAlgorithm('SHA512');
```

<p align="center">
  <a href="https://www.turnon2fa.com">
    <img alt="2FA ALL THE THINGS!" src="https://raw.githubusercontent.com/chillerlan/php-authenticator/master/stuff/2fa-all-the-things.jpg">
  </a>
</p>
