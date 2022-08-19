<?php

namespace Mika56\SPFCheck\Test;


use Mika56\SPFCheck\DNS\DNSRecordGetterInterface;
use Mika56\SPFCheck\Exception\DNSLookupLimitReachedException;

class DNSRecordGetterIssue7 implements DNSRecordGetterInterface
{

    public function getSPFRecordsForDomain(string $domain): array
    {
        return array();
    }

    public function resolveA(string $domain, bool $ip4only = false): array
    {
    }

    public function resolveMx(string $domain): array
    {
    }

    public function resolvePtr(string $ipAddress): array
    {
    }

}
