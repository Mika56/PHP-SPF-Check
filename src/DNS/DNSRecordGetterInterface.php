<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\DNS;


use Mika56\SPFCheck\Exception\DNSLookupException;

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

    /**
     * @return string[]
     * @throws DNSLookupException
     */
    public function resolveMx(string $domain): array;

    /**
     * @return string[]
     * @throws DNSLookupException
     */
    public function resolvePtr(string $ipAddress): array;

    /**
     * @return string[]
     * @throws DNSLookupException
     */
    public function resolveTXT(string $domain): array;

}
