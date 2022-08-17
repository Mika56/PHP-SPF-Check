<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\Test;

use Mika56\SPFCheck\DNSRecordGetterInterface;
use Mika56\SPFCheck\Exception\DNSLookupException;
use Mika56\SPFCheck\Exception\DNSLookupLimitReachedException;

/**
 * Class that understands OpenSPF's DNS records
 */
class DNSRecordGetterOpenSPF implements DNSRecordGetterInterface
{
    protected array $data;
    protected int $requestCount;
    protected int $requestMXCount = 0;
    protected int $requestPTRCount = 0;

    public function __construct(array $data)
    {
        $this->data = array();
        foreach ($data as $domain => $zones) {
            $domain              = strtolower($domain);
            $this->data[$domain] = array();
            foreach ($zones as $zone) {
                if ($zone == 'TIMEOUT') {
                    $this->data[$domain] = 'TIMEOUT';
                }
                if (is_array($zone)) {
                    foreach ($zone as $type => $value) {
                        if (!array_key_exists($type, $this->data[$domain])) {
                            $this->data[$domain][$type] = array();
                        }
                        if (($type == 'TXT' || $type == 'SPF') && is_array($value)) {
                            $value = implode('', $value);
                        }
                        $this->data[$domain][$type][] = $value;
                    }
                }
            }
        }
    }

    public function getSPFRecordForDomain(string $domain): array
    {
        $domain     = strtolower($domain);
        $spfRecords = array();
        if (array_key_exists($domain, $this->data)) {
            if ($this->data[$domain] == 'TIMEOUT') {
                throw new DNSLookupException();
            }
            $spf = array();

            if (array_key_exists('SPF', $this->data[$domain]) && !array_key_exists('TXT', $this->data[$domain])) {
                $spf = $this->data[$domain]['SPF'];
            } elseif (array_key_exists('TXT', $this->data[$domain])) {
                $spf = $this->data[$domain]['TXT'];
            }
            if (!is_array($spf)) {
                $spf = array($spf);
            }

            foreach ($spf as $record) {
                $record = strtolower($record);
                if ($record == 'v=spf1' || stripos($record, 'v=spf1 ') === 0) {
                    $spfRecords[] = $record;
                }
            }
        }

        return $spfRecords;
    }

    public function resolveA(string $domain, $ip4only = false): array
    {
        $domain    = strtolower($domain);
        $addresses = array();
        if (array_key_exists($domain, $this->data)) {
            if (array_key_exists('A', $this->data[$domain])) {
                $addresses = array_merge($addresses, $this->data[$domain]['A']);
            }
            if (!$ip4only && array_key_exists('AAAA', $this->data[$domain])) {
                $addresses = array_merge($addresses, $this->data[$domain]['AAAA']);
            }
        }

        return $addresses;
    }

    public function resolveMx(string $domain): array
    {
        $domain    = strtolower($domain);
        $mxServers = array();
        if (array_key_exists($domain, $this->data) && $this->data[$domain] != 'TIMEOUT' && array_key_exists('MX', $this->data[$domain])) {
            $mx = $this->data[$domain]['MX'];
            usort($mx, function ($a, $b) {
                if ($a[0] == $b[0]) {
                    return 0;
                }

                return ($a[0] < $b[0]) ? -1 : 1;
            });
            foreach ($mx as $server) {
                $mxServers[] = $server[1];
            }
        }

        return $mxServers;
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

        if (array_key_exists($revIp, $this->data) && array_key_exists('PTR', $this->data[$revIp])) {
            return array_slice($this->data[$revIp]['PTR'], 0, 10);
        }

        return array();
    }

    public function exists(string $domain): bool
    {
        $domain = strtolower($domain);

        if (array_key_exists($domain, $this->data)) {
            if ($this->data[$domain] == 'TIMEOUT') {
                throw new DNSLookupException();
            }

            return count($this->resolveA($domain, true)) > 0;
        }

        return false;
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
