# PHP-SPF-Check
[![Build Status](https://travis-ci.org/Mika56/PHP-SPF-Check.svg?branch=master)](https://travis-ci.org/Mika56/PHP-SPF-Check)
[![Latest Stable Version](https://poser.pugx.org/mika56/spfcheck/v/stable)](https://packagist.org/packages/mika56/spfcheck)
[![Total Downloads](https://poser.pugx.org/mika56/spfcheck/downloads)](https://packagist.org/packages/mika56/spfcheck)
[![License](https://poser.pugx.org/mika56/spfcheck/license)](https://packagist.org/packages/mika56/spfcheck)
[![Coverage Status](https://coveralls.io/repos/github/Mika56/PHP-SPF-Check/badge.svg)](https://coveralls.io/github/Mika56/PHP-SPF-Check)

Simple library to check an IP address against a domain's [SPF](http://www.openspf.org/) record

## Installation
This library is available through Composer.
Run `composer require mika56/spfcheck` or add this to your composer.json:
```json
{
  "require": {
    "mika56/spfcheck": "dev-master"
  }
}
```

## Usage
Create a new instance of SPFCheck. The constructor requires a DNSRecordGetterInterface to be passed. Currently, only DNSRecordGetter exists, which uses PHP's DNS functions to get data.
```php
<?php
use Mika56\SPFCheck\SPFCheck;
use Mika56\SPFCheck\DNSRecordGetter;

require('vendor/autoload.php');
$checker = new SPFCheck(new DNSRecordGetter());
var_dump($checker->isIPAllowed('127.0.0.1', 'test.com'));
```

Return value is one of `SPFCheck::RESULT_PASS`, `SPFCheck::RESULT_FAIL`, `SPFCheck::RESULT_SOFTFAIL`, `SPFCheck::RESULT_NEUTRAL`, `SPFCheck::RESULT_NONE`, `SPFCheck::RESULT_PERMERROR`, `SPFCheck::RESULT_TEMPERROR`

## Missing features
A few features are still missing from this library at the moment. Here's a partial list of those features:
* [Section 7 of RFC7208](https://tools.ietf.org/html/rfc7208#section-7) on macros

You are very welcome to submit a pull request adding even part of those features.