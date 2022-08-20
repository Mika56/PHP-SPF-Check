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
    "mika56/spfcheck": "^2.0"
  }
}
```

## Usage
Create a new instance of SPFCheck. The constructor requires a DNSRecordGetterInterface to be passed. Currently, you have two options:
- `DNSRecordGetter` which uses PHP's DNS functions to get data
- `DNSRecordGetterDirect` which uses the [PHP DNS Direct Query Module](https://github.com/purplepixie/phpdns) to get data.

```php
<?php
use Mika56\SPFCheck\DNS\DNSRecordGetter;
use Mika56\SPFCheck\DNS\DNSRecordGetterDirect;
use Mika56\SPFCheck\SPFCheck;

require('vendor/autoload.php');

$checker = new SPFCheck(new DNSRecordGetter()); // Uses php's dns_get_record method for lookup.
var_dump($checker->getIPStringResult('127.0.0.1', 'test.com'));

// or

$checker = new SPFCheck(new DNSRecordGetterDirect("8.8.8.8")); // Uses phpdns, allowing you to set the nameserver you wish to use for the dns queries.
var_dump($checker->getIPStringResult('127.0.0.1', 'test.com'));
```

Return value is one of `Result::PASS`, `Result::FAIL`, `Result::SOFTFAIL`, `Result::NEUTRAL`, `Result::NONE`, `Result::PERMERROR`, `Result::TEMPERROR`

If you want to get more details about the check, you can use `SPFCheck::getIPResult(string $ipAddress, string $domainName): Result` which will return a 
`Result` object with more details about the check.
