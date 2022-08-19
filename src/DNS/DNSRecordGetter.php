<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\DNS;


use Mika56\SPFCheck\Exception\DNSLookupException;

class DNSRecordGetter implements DNSRecordGetterInterface
{
    /**
     * @param string $domain The domain to get SPF record
     * @return string[] The SPF record(s)
     * @throws DNSLookupException
     */
    public function getSPFRecordsForDomain(string $domain): array
    {
        $records = dns_get_record($domain, DNS_TXT | DNS_SOA);
        if (false === $records) {
            throw new DNSLookupException;
        }

        $spfRecords = [];
        foreach ($records as $record) {
            if ($record['type'] !== 'TXT') {
                continue;
            }
            $txt = strtolower($record['txt']);
            // An SPF record can be empty (no mechanism)
            if ($txt == 'v=spf1' || str_starts_with($txt, 'v=spf1 ')) {
                $spfRecords[] = $txt;
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

}