# PHP-SPF-Check

[![CI](https://github.com/Mika56/PHP-SPF-Check/actions/workflows/ci.yml/badge.svg)](https://github.com/Mika56/PHP-SPF-Check/actions/workflows/ci.yml)
[![Latest Stable Version](https://poser.pugx.org/mika56/spfcheck/v/stable)](https://packagist.org/packages/mika56/spfcheck)
[![Total Downloads](https://poser.pugx.org/mika56/spfcheck/downloads)](https://packagist.org/packages/mika56/spfcheck)
[![License](https://poser.pugx.org/mika56/spfcheck/license)](https://packagist.org/packages/mika56/spfcheck)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/04f2a3a221c143089126d70f235a54cd)](https://app.codacy.com/gh/Mika56/PHP-SPF-Check/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=Mika56/PHP-SPF-Check&amp;utm_campaign=Badge_Grade)
[![Codacy Badge](https://app.codacy.com/project/badge/Coverage/04f2a3a221c143089126d70f235a54cd)](https://app.codacy.com/gh/Mika56/PHP-SPF-Check/dashboard?utm_source=github.com&utm_medium=referral&utm_content=Mika56/PHP-SPF-Check&utm_campaign=Badge_Coverage)

Simple library to check an IP address against a domain's [SPF](http://www.openspf.org/) record

## Requirements
This library requires a supported version of PHP, that is PHP >= 8.1.

Older versions of this library support older versions of PHP. Please note that no bugfixes, no new features, and no support will be provided for older versions.

| Library version | Min version of PHP | Highest version of PHP |
|-----------------|--------------------|------------------------|
| 1               | 5.6                | 5.6                    |
| 2               | 7.4                | 8.3                    |
| 3               | 8.1                | 8.4                    |

## Installation
This library is available through Composer.
Run `composer require "mika56/spfcheck:^3.0"` or add this to your composer.json:
```json
{
  "require": {
    "mika56/spfcheck": "^3.0"
  }
}
```

## Usage
Create a new instance of SPFCheck. The constructor requires a DNSRecordGetterInterface to be passed. Included in this library is `DNSRecordGetter`, 
which uses PHP's DNS function `dns_get_record` to get data. Please take a look at [mika56/spfcheck-dns-direct](https://github.com/Mika56/PHP-SPF-Check-DNS-Direct) 
if you want to use custom DNS servers.

```php
<?php
use Mika56\SPFCheck\DNS\DNSRecordGetter;
use Mika56\SPFCheck\SPFCheck;

require('vendor/autoload.php');

$checker = new SPFCheck(new DNSRecordGetter());
var_dump($checker->getIPStringResult('127.0.0.1', 'test.com'));
```

Return value is one of `Result::SHORT_PASS`, `Result::SHORT_FAIL`, `Result::SHORT_SOFTFAIL`, `Result::SHORT_NEUTRAL`, `Result::SHORT_NONE`, `Result::SHORT_PERMERROR`,
`Result::SHORT_TEMPERROR`

If you want to get more details about the check, you can use `SPFCheck::getResult(Query $query): Result` which will return a `Result` object with more details about the check.
