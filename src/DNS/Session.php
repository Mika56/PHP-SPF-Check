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

    public function __construct(DNSRecordGetterInterface $DNSRecordGetter)
    {
        $this->DNSRecordGetter = $DNSRecordGetter;
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
        if ($this->requestCount++ == 10) {
            throw new DNSLookupLimitReachedException();
        }
    }

    /**
     * @throws DNSLookupLimitReachedException
     */
    private function countMXRequest(): void
    {
        if (++$this->requestMXCount > 10) {
            throw new DNSLookupLimitReachedException();
        }
    }

    /**
     * @throws DNSLookupLimitReachedException
     */
    private function countPTRRequest(): void
    {
        if (++$this->requestPTRCount > 10) {
            throw new DNSLookupLimitReachedException();
        }
    }


}
