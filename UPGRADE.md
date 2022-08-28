# UPGRADE FROM 1.x TO 2.0

## PHP Version

Version 2.0 now requires a supported PHP version, that is PHP 7.4 and >= 8.0

## Public methods of `SPFCheck`

The available methods of `SPFCheck` has changed.

```php
# removed
public function isIPAllowed($ipAddress, $domain);
# replaced by
public function getIPStringResult(string $ipAddress, string $domain): string;

# added
public function getDomainSPFRecords(string $domainName): array;
public function getResult(Query $query): Result;
```

## `DNSRecordGetter` moved to the `Mika56\SPFCheck\DNS` namespace

```php
# before
use Mika56\SPFCheck\DNSRecordGetter;
use Mika56\SPFCheck\SPFCheck;

$checker = new SPFCheck(new DNSRecordGetter());

# after
use Mika56\SPFCheck\DNS\DNSRecordGetter;
use Mika56\SPFCheck\SPFCheck;

$checker = new SPFCheck(new DNSRecordGetter());
```

## `DNSRecordGetterDirect` moved to its own repository

The class has been moved to [mika56/spfcheck-dns-direct](https://github.com/Mika56/PHP-SPF-Check-DNS-Direct). This removed the dependency on `purplepixie/phpdns`. 
