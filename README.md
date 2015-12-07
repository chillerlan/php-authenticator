# php-googleauth

[![Packagist](https://img.shields.io/packagist/v/chillerlan/php-googleauth.svg?style=flat-square)](https://packagist.org/packages/chillerlan/php-googleauth)
[![License](https://img.shields.io/packagist/l/chillerlan/php-googleauth.svg?style=flat-square)](LICENSE)
[![Travis Build Status](https://img.shields.io/travis/chillerlan/php-googleauth.svg?style=flat-square)](https://travis-ci.org/chillerlan/php-googleauth)
[![codecov.io](https://img.shields.io/codecov/c/github/chillerlan/php-googleauth.svg?style=flat-square)](https://codecov.io/github/chillerlan/php-googleauth?branch=master)

Yet another Google Authenticator implementation! Well, it's mostly a fork of [PHPGangsta](https://github.com/PHPGangsta/GoogleAuthenticator/), cleaned up and with new features.

[2FA ALL THE THINGS!](https://www.turnon2fa.com)

## Requirements
- PHP 5.6+, PHP 7

## Documentation

### Installation
#### Using [composer](https://getcomposer.org)

*Terminal*
```sh
composer require chillerlan/php-googleauth:dev-master
```

*composer.json*
```json
{
	"require": {
		"php": ">=5.6.0",
		"chillerlan/php-googleauth": "dev-master"
	}
}
```

#### Manual installation
Download the desired version of the package from [master](https://github.com/codemasher/php-googleauth/archive/master.zip) or 
[release](https://github.com/codemasher/php-googleauth/releases) and extract the contents to your project folder. 
Point the namespace `chillerlan/GoogleAuth` to the folder `src` of the package.

Profit!

### Usage

The secret is usually being created once during the activetion process in a user control panel. 
So all you need to do there is to create a code and display it to the user in a convenient way, as text string and QR code for example.
```php
// create a secret (stored somewhere on the server *coughs*)
$secret = Authenticator::createSecret();

// you can also specify the length
$secret = Authenticator::createSecret(20);
```

In order to display a QR code, you can use one of the following methods.
- `$label` should be something that identifies the account to which the secret belongs
- `$issuer` is the name of your website or company for example, so that the user is able to identify multiple accounts.
```php
// -> otpauth://totp/test?secret=NKSOQG7UKKID4IXW&issuer=chillerlan.net
$uri = Authenticator::getUri($secret, $label, $issuer);

// -> https://chart.googleapis.com/chart?chs=200x200&chld=M%7C0&cht=qr&chl=otpauth%3A%2F%2Ftotp%2Ftest%3Fsecret%3DNKSOQG7UKKID4IXW%26issuer%3Dchillerlan.net
$uri = Authenticator::getGoogleQr($secret, $label, $issuer);
```

Now during the login process - after the user has successfully entered their credentials - you would 
ask them for a one time code to check it against the secret from your user database.
```php
// verify the code
if(Authenticator::verifyCode($code, $secret)){
	// that's it - 2FA has never been easier! :D
}

// or just the strict method...
if((string)$_POST['code'] === Authenticator::getCode($secret)){
	// verified
}

// ...which is equivalent to
if(Authenticator::verifyCode($code, $secret, null, 0)){
	// verified
}

```

If your authenticator produces wrong one time codes, you may want to check your timezone settings.
In case you can't adjust them server side, you can do it in the script like so:
```php
// let's say, your server's timezone is an hour off
$timestamp = time() - 3600;
$timeslice = floor($timestamp / Authenticator::$period);

if(Authenticator::verifyCode($code, $secret, $timeslice)){
	//  verified
}

if((string)$_POST['code'] === Authenticator::getCode($secret, $timeslice)){
	// verified
}

```

There are 2 other methods which are not (yet) supported by Google Authenticator but mabe useful in other implementations:
```php
// see https://github.com/google/google-authenticator/wiki/Key-Uri-Format#parameters

// code length, currently 6 or 8
Authenticator::setDigits(8);

// valid period between 10 and 60 seconds
Authenticator::setPeriod(45);
```
