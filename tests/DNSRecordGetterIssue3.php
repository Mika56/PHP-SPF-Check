<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\Test;

use Mika56\SPFCheck\DNS\DNSRecordGetterInterface;
use Mika56\SPFCheck\Exception\DNSLookupException;
use Mika56\SPFCheck\Exception\DNSLookupLimitReachedException;

class DNSRecordGetterIssue3 implements DNSRecordGetterInterface
{

    protected array $spfRecords = [
        'domain.com' => 'v=spf1 include:domain.com ~all',
    ];

    public function getSPFRecordsForDomain(string $domain): array
    {
        if (array_key_exists($domain, $this->spfRecords)) {
            if ($this->spfRecords[$domain] == '') {
                return [];
            }

            return array($this->spfRecords[$domain]);
        }

        throw new DNSLookupException;
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
