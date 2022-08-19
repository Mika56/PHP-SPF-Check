<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\DNS;


use Mika56\SPFCheck\Exception\DNSLookupException;
use Mika56\SPFCheck\Exception\DNSLookupLimitReachedException;

interface DNSRecordGetterInterface
{
    /**
     * @return string[]
     * @throws DNSLookupException
     */
    public function getSPFRecordsForDomain(string $domain): array;

    /**
     * @return string[]
     * @throws DNSLookupException
     */
    public function resolveA(string $domain, bool $ip4only = false): array;

    public function resolveMx(string $domain): array;

    public function resolvePtr(string $ipAddress): array;

    /**
     * @throws DNSLookupException
     */
    public function exists(string $domain): bool;

    /**
     * Reset all request counters (A/AAAA, MX, PTR)
     * @return void
     */
    public function resetRequestCounts(): void;

    /**
     * Count a A/AAAA request
     * @throws DNSLookupLimitReachedException
     * @return void
     */
    public function countRequest(): void;

    /**
     * Count an MX request
     * @throws DNSLookupLimitReachedException
     * @return void
     */
    public function countMxRequest(): void;

    /**
     * Count a PTR request
     * @throws DNSLookupLimitReachedException
     * @return void
     */
    public function countPtrRequest(): void;
}
