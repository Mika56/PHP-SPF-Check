<?php
/**
 *
 * @author Mikael Peigney
 */

namespace Mika56\SPFCheck;


use Mika56\SPFCheck\Exception\DNSLookupException;
use Mika56\SPFCheck\Exception\DNSLookupLimitReachedException;

class DNSRecordGetter implements DNSRecordGetterInterface
{
    protected $requestCount = 0;

    /**
     * @param $domain string The domain to get SPF record
     * @return string[] The SPF record(s)
     * @throws DNSLookupException
     */
    public function getSPFRecordForDomain($domain)
    {
        $records = dns_get_record($domain, DNS_TXT | DNS_SOA);
        if (false === $records) {
            throw new DNSLookupException;
        }

        $spfRecords = array();
        foreach ($records as $record) {
            if (array_key_exists('txt', $record)) {
                $txt = strtolower($record['txt']);
                // An SPF record can be empty (no mechanism)
                if ($record == 'v=spf1' || stripos($txt, 'v=spf1 ') === 0) {
                    $spfRecords[] = $txt;
                }
            }
        }

        return $spfRecords;
    }

    public function resolveA($domain, $ip4only = false)
    {
        $records = dns_get_record($domain, $ip4only ? DNS_A : (DNS_A | DNS_AAAA));
        if (false === $records) {
            throw new DNSLookupException;
        }

        $addresses = [];

        foreach ($records as $record) {
            if (array_key_exists('a', $record)) {
                $addresses[] = $record['a'];
            } elseif (array_key_exists('aaaa', $record)) {
                $addresses[] = $record['aaaa'];
            }
        }

        return $addresses;
    }

    public function resolveMx($domain)
    {
        $records = dns_get_record($domain, DNS_MX);
        if (false === $records) {
            throw new DNSLookupException;
        }

        $addresses = [];

        foreach ($records as $record) {
            if (array_key_exists('mx', $record)) {
                $addresses[] = $record['mx'];
            }
        }

        return $addresses;
    }

    public function resolvePtr($ipAddress)
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

        $revs = array_map(function ($e) {
            return $e['target'];
        }, dns_get_record($revIp, DNS_PTR));

        return array_slice($revs, 0, 10);
    }

    public function exists($domain)
    {
        return count($this->resolveA($domain, true)) > 0;
    }

    public function resetRequestCount()
    {
        $this->requestCount = 0;
    }

    public function countRequest()
    {
        if (++$this->requestCount > 10) {
            throw new DNSLookupLimitReachedException();
        }
    }
}