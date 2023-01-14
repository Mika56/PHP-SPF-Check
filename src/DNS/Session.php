<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\DNS;

use Mika56\SPFCheck\Exception\DNSLookupException;
use Mika56\SPFCheck\Exception\DNSLookupLimitReachedException;

final class Session
{
    private DNSRecordGetterInterface $DNSRecordGetter;
    protected int $requestCount = 0;
    protected int $requestMXCount = 0;
    protected int $requestPTRCount = 0;
    private int $maxRequests;
    private int $maxMXRequests;
    private int $maxPTRRequests;

    public function __construct(DNSRecordGetterInterface $DNSRecordGetter, int $maxRequests = 10, int $maxMXRequests = 10, int $maxPTRRequests = 10)
    {
        $this->DNSRecordGetter = $DNSRecordGetter;
        $this->maxRequests = $maxRequests;
        $this->maxMXRequests = $maxMXRequests;
        $this->maxPTRRequests = $maxPTRRequests;
    }

    /**
     * @throws DNSLookupLimitReachedException
     * @throws DNSLookupException
     */
    public function resolveA(string $domainName, bool $ipv4Only = false): iterable
    {
        $this->countRequest();

        return $this->DNSRecordGetter->resolveA($domainName, $ipv4Only);
    }

    /**
     * @throws DNSLookupLimitReachedException
     */
    public function resolveMX(string $domainName): iterable
    {
        $this->countRequest();
        $records = $this->DNSRecordGetter->resolveMx($domainName);
        foreach ($records as $record) {
            $this->countMXRequest();
            // MX records shouldn't be empty, best practice is to ignore them when they are
            if(empty($record)) {
                continue;
            }
            // Although not recommended, an MX record can be an IP address
            if(false !== filter_var($record, FILTER_VALIDATE_IP)) {
                yield [$record];
            }
            else {
                yield $this->DNSRecordGetter->resolveA($record);
            }
        }
    }

    /**
     * @throws DNSLookupLimitReachedException
     */
    public function resolvePTR(string $ipAddress): iterable
    {
        $this->countRequest();

        $ptrRecords = $this->DNSRecordGetter->resolvePtr($ipAddress);
        foreach ($ptrRecords as $i => $ptrRecord) {
            if($i > 9) {
                // "if more than 10 sending-domain_names are found, use at most 10"
                return;
            }
            $this->countPTRRequest();
            $ptrRecord = strtolower($ptrRecord);
            $ipAddresses = $this->DNSRecordGetter->resolveA($ptrRecord);
            if (in_array($ipAddress, $ipAddresses)) {
                yield $ptrRecord;
            }
        }
    }

    /**
     * @throws DNSLookupException
     */
    public function resolveTXT(string $hostname): array
    {
        return $this->DNSRecordGetter->resolveTXT($hostname);
    }

    public function getRequestCount(): int
    {
        return $this->requestCount;
    }

    public function getRequestMXCount(): int
    {
        return $this->requestMXCount;
    }

    public function getRequestPTRCount(): int
    {
        return $this->requestPTRCount;
    }

    /**
     * @throws DNSLookupLimitReachedException
     */
    public function countRedirect(): void
    {
        $this->countRequest();
    }

    /**
     * @throws DNSLookupLimitReachedException
     */
    private function countRequest(): void
    {
        if ($this->requestCount++ == $this->maxRequests) {
            throw new DNSLookupLimitReachedException();
        }
    }

    /**
     * @throws DNSLookupLimitReachedException
     */
    private function countMXRequest(): void
    {
        if (++$this->requestMXCount > $this->maxMXRequests) {
            throw new DNSLookupLimitReachedException();
        }
    }

    /**
     * @throws DNSLookupLimitReachedException
     */
    private function countPTRRequest(): void
    {
        if (++$this->requestPTRCount > $this->maxPTRRequests) {
            throw new DNSLookupLimitReachedException();
        }
    }


}
