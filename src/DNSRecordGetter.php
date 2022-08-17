<?php

declare(strict_types=1);

namespace Mika56\SPFCheck;


use Mika56\SPFCheck\Exception\DNSLookupException;
use Mika56\SPFCheck\Exception\DNSLookupLimitReachedException;

class DNSRecordGetter implements DNSRecordGetterInterface
{
    protected int $requestCount = 0;
    protected int $requestMXCount = 0;
    protected int $requestPTRCount = 0;

    /**
     * @param string $domain The domain to get SPF record
     * @return string[] The SPF record(s)
     * @throws DNSLookupException
     */
    public function getSPFRecordForDomain(string $domain): array
    {
        $records = dns_get_record($domain, DNS_TXT | DNS_SOA);
        if (false === $records) {
            throw new DNSLookupException;
        }

        $spfRecords = array();
        foreach ($records as $record) {
            if ($record['type'] == 'TXT') {
                $txt = strtolower($record['txt']);
                // An SPF record can be empty (no mechanism)
                if ($txt == 'v=spf1' || stripos($txt, 'v=spf1 ') === 0) {
                    $spfRecords[] = $txt;
                }
            }
        }

        return $spfRecords;
    }

    /**
     * @throws DNSLookupException
     */
    public function resolveA(string $domain, bool $ip4only = false): array
    {
        $records = dns_get_record($domain, $ip4only ? DNS_A : (DNS_A | DNS_AAAA));
        if (false === $records) {
            throw new DNSLookupException;
        }

        $addresses = [];

        foreach ($records as $record) {
            if ($record['type'] === "A") {
                $addresses[] = $record['ip'];
            } elseif ($record['type'] === 'AAAA') {
                $addresses[] = $record['ipv6'];
            }
        }

        return $addresses;
    }

    /**
     * @throws DNSLookupException
     */
    public function resolveMx(string $domain): array
    {
        $records = dns_get_record($domain, DNS_MX);
        if (false === $records) {
            throw new DNSLookupException;
        }

        $addresses = [];

        foreach ($records as $record) {
            if ($record['type'] === "MX") {
                $addresses[] = $record['target'];
            }
        }

        return $addresses;
    }

    public function resolvePtr(string $ipAddress): array
    {
        if (stripos($ipAddress, '.') !== false) {
            // IPv4
            $revIp = implode('.', array_reverse(explode('.', $ipAddress))).'.in-addr.arpa';
        } else {
            $literal = implode(':', array_map(function ($b) {
                return sprintf('%04x', $b);
            }, unpack('n*', inet_pton($ipAddress))));
            $revIp   = strtolower(implode('.', array_reverse(str_split(str_replace(':', '', $literal))))).'.ip6.arpa';
        }

        return array_map(function ($e) {
            return $e['target'];
        }, dns_get_record($revIp, DNS_PTR));
    }

    public function exists(string $domain): bool
    {
        try {
            return count($this->resolveA($domain, true)) > 0;
        } catch (DNSLookupException $e) {
            return false;
        }
    }

    public function countRequest(): void
    {
        if ($this->requestCount++ == 10) {
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
