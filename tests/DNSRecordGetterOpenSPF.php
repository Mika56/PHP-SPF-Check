<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\Test;

use Mika56\SPFCheck\DNS\DNSRecordGetterInterface;
use Mika56\SPFCheck\Exception\DNSLookupException;

/**
 * Class that understands OpenSPF's DNS records
 */
class DNSRecordGetterOpenSPF implements DNSRecordGetterInterface
{
    protected array $data;

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

    public function resolveA(string $domain, $ip4only = false): array
    {
        $domain    = strtolower($domain);
        $addresses = array();
        if(empty($domain)) {
            throw new DNSLookupException();
        }
        if (array_key_exists($domain, $this->data)) {
            if ($this->data[$domain] == 'TIMEOUT') {
                throw new DNSLookupException();
            }
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

    public function resolveTXT(string $domain): array
    {
        $domain    = strtolower($domain);
        if (array_key_exists($domain, $this->data)) {
            if ($this->data[$domain] == 'TIMEOUT') {
                throw new DNSLookupException();
            }

            $spf = [];

            // Although we're asking for TXT records, a lot of OpenSPF tests uses the deprecated SPF record type
            if (array_key_exists('SPF', $this->data[$domain]) && !array_key_exists('TXT', $this->data[$domain])) {
                $spf = $this->data[$domain]['SPF'];
            } elseif (array_key_exists('TXT', $this->data[$domain])) {
                $spf = $this->data[$domain]['TXT'];
            }
            if (!is_array($spf)) {
                $spf = [$spf];
            }

            return $spf;
        }

        return [];
    }
}
