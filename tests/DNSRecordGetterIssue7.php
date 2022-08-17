<?php

namespace Mika56\SPFCheck\Test;


use Mika56\SPFCheck\DNSRecordGetterInterface;
use Mika56\SPFCheck\Exception\DNSLookupLimitReachedException;

class DNSRecordGetterIssue7 implements DNSRecordGetterInterface
{
    protected int $requestCount = 0;
    protected int $requestMXCount = 0;
    protected int $requestPTRCount = 0;

    protected array $spfRecords = [];

    public function getSPFRecordForDomain(string $domain): array
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

    public function exists(string $domain): bool
    {
    }

    public function resetRequestCount(): void
    {
        trigger_error('DNSRecordGetterInterface::resetRequestCount() is deprecated. Please use resetRequestCounts() instead', E_USER_DEPRECATED);
        $this->resetRequestCounts();
    }

    public function countRequest(): void
    {
        if (++$this->requestCount > 10) {
            throw new DNSLookupLimitReachedException();
        }
    }

    public function resetRequestCounts(): void
    {
        $this->requestCount    = 0;
        $this->requestMXCount  = 0;
        $this->requestPTRCount = 0;
    }

    public function countMxRequest(): void
    {
        if (++$this->requestMXCount > 10) {
            throw new DNSLookupLimitReachedException();
        }
    }

    public function countPtrRequest(): void
    {
        if (++$this->requestPTRCount > 10) {
            throw new DNSLookupLimitReachedException();
        }
    }
}
