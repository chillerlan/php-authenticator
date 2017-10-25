# php-googleauth

[![version][packagist-badge]][packagist]
[![license][license-badge]][license]
[![Travis][travis-badge]][travis]
[![Coverage][coverage-badge]][coverage]
[![Scrunitizer][scrutinizer-badge]][scrutinizer]
[![Code Climate][codeclimate-badge]][codeclimate]
[![Downloads][downloads-badge]][downloads]

[packagist-badge]: https://img.shields.io/packagist/v/chillerlan/php-googleauth.svg?style=flat-square
[packagist]: https://packagist.org/packages/chillerlan/php-googleauth
[license-badge]: https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square
[license]: https://github.com/codemasher/php-googleauth/blob/master/LICENSE
[travis-badge]: https://img.shields.io/travis/codemasher/php-googleauth.svg?style=flat-square
[travis]: https://travis-ci.org/codemasher/php-googleauth
[coverage-badge]: https://img.shields.io/codecov/c/github/codemasher/php-googleauth.svg?style=flat-square
[coverage]: https://codecov.io/github/codemasher/php-googleauth
[scrutinizer-badge]: https://scrutinizer-ci.com/g/codemasher/php-googleauth/badges/quality-score.png?b=master
[scrutinizer]: https://scrutinizer-ci.com/g/codemasher/php-googleauth
[codeclimate-badge]: https://img.shields.io/codeclimate/github/codemasher/php-googleauth.svg
[codeclimate]: https://codeclimate.com/github/codemasher/php-googleauth
[downloads-badge]: https://img.shields.io/packagist/dt/chillerlan/php-googleauth.svg
[downloads]: https://packagist.org/packages/chillerlan/php-googleauth/stats

Yet another Google Authenticator implementation!

# Documentation
## Requirements
- PHP 7+

## Installation
### Using [composer](https://getcomposer.org)

*Terminal*
```sh
composer require chillerlan/php-googleauth:dev-master
```

*composer.json*
```json
{
	"require": {
		"php": ">=7.0.3",
		"chillerlan/php-googleauth": "dev-master"
	}
}
```

Profit!

## Usage

### Creating a secret 
The secret is usually being created once during the activation process in a user control panel. 
So all you need to do there is to create a secret and display it to the user in a convenient way, as text string and QR code for example.
```php
$authenticator = new Authenticator;

// create a secret (stored somewhere in a safe place on the server *coughs*)
$secret = $authenticator->createSecret();

// you can also specify the length of the secret key
$secret = $authenticator->createSecret(20);
```

In order to display a QR code, you can use one of the following methods.
- `$label` should be something that identifies the account to which the secret belongs
- `$issuer` is the name of your website or company for example, so that the user is able to identify multiple accounts.
```php
// -> otpauth://totp/test?secret=NKSOQG7UKKID4IXW&issuer=chillerlan.net
$uri = $authenticator->getUri($secret, $label, $issuer);
```

### Verify a one time code
Now during the login process - after the user has successfully entered their credentials - you would 
ask them for a one time code to check it against the secret from your user database.
```php
// verify the code
if($authenticator->verifyCode($code, $secret)){
	// that's it - 2FA has never been easier! :D
}

// or just the strict method...
if(hash_equals($authenticator->getCode($secret), $_POST['code'])){
	// verified
}

// ...which is equivalent to
if($authenticator->verifyCode($code, $secret, null, 0)){
	// verified
}

```

### Advanced settings
If your authenticator produces wrong one time codes, you may want to check your timezone settings.
In case you can't adjust them server side, you can do it in the script like so:
```php
// let's say, your server's timezone is an hour off
$timestamp = time() - 3600;
$timeslice = floor($timestamp / $authenticator->$period);

if($authenticator->verifyCode($code, $secret, $timeslice)){
	//  verified
}

if(hash_equals($authenticator->getCode($secret, $timeslice), $_POST['code'])){
	// verified
}

```

There are 2 other methods which are not (yet) supported by Google Authenticator but mabe useful in other implementations:
```php
// see https://github.com/google/google-authenticator/wiki/Key-Uri-Format#parameters

// code length, currently 6 or 8
$authenticator->setDigits(8);

// valid period between 10 and 60 seconds
$authenticator->setPeriod(45);

// set these values via the constructor
$authenticator = new Authenticator(20, 8); // $period, $digits
```

<p align="center">
  <a href="https://www.turnon2fa.com">
    <img alt="2FA ALL THE THINGS!" src="https://raw.githubusercontent.com/codemasher/php-googleauth/master/stuff/2fa-all-the-things.jpg">
  </a>
</p>
