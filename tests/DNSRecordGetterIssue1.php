<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\Test;


use Mika56\SPFCheck\DNS\DNSRecordGetterInterface;
use Mika56\SPFCheck\Exception\DNSLookupException;

class DNSRecordGetterIssue1 implements DNSRecordGetterInterface
{
    protected array $spfRecords = [
        'domaina.com' => 'v=spf1 include:domainb.com include:domainc.com -all',
        'domainb.com' => 'v=spf1 -all',
        'domainc.com' => 'v=spf1 +ip4:127.0.0.1 -all',
    ];

    protected $aRecords = [];

    protected $mxRecords = [];

    protected $ptrRecords = [];

    public function getSPFRecordsForDomain(string $domain): array
    {
        if (array_key_exists($domain, $this->spfRecords)) {
            if ($this->spfRecords[$domain] == '') {
                return false;
            }

            return array($this->spfRecords[$domain]);
        }

        throw new DNSLookupException;
    }

    public function resolveA(string $domain, bool $ip4only = false): array
    {
        if (array_key_exists($domain, $this->aRecords)) {
            return $this->aRecords[$domain];
        }

        return false;
    }

    public function resolveMx(string $domain): array
    {
        if (array_key_exists($domain, $this->mxRecords)) {
            return $this->mxRecords[$domain];
        }

        return false;
    }

    public function resolvePtr(string $ipAddress): array
    {
        if (array_key_exists($ipAddress, $this->ptrRecords)) {
            return $this->ptrRecords[$ipAddress];
        }

        return false;
    }

    public function resolveTXT(string $domain): array
    {
        return [];
    }
}
