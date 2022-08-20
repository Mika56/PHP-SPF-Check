<?php

namespace Mika56\SPFCheck\Test;


use Mika56\SPFCheck\DNS\DNSRecordGetterInterface;
use Mika56\SPFCheck\Exception\DNSLookupLimitReachedException;

class DNSRecordGetterIssue7 implements DNSRecordGetterInterface
{

    public function getSPFRecordsForDomain(string $domain): array
    {
        return [];
    }

    public function resolveA(string $domain, bool $ip4only = false): array
    {
        return [];
    }

    public function resolveMx(string $domain): array
    {
        return [];
    }

    public function resolvePtr(string $ipAddress): array
    {
        return [];
    }

    public function resolveTXT(string $domain): array
    {
        return [];
    }
}
