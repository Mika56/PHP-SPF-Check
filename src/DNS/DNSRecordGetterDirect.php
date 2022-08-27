<?php

declare(strict_types=1);
/**
 * @author Brian Tafoya <btafoya@briantafoya.com>
 */

namespace Mika56\SPFCheck\DNS;

use Mika56\SPFCheck\Exception\DNSLookupException;
use PurplePixie\PhpDns\DNSQuery;

class DNSRecordGetterDirect implements DNSRecordGetterInterface
{

    protected string $nameserver = "8.8.8.8";
    protected int $port = 53;
    protected int $timeout = 30;
    protected bool $udp = true;
    protected bool $tcpFallback;

    public function __construct(string $nameserver = '8.8.8.8', int $port = 53, int $timeout = 30, bool $udp = true, bool $tcpFallback = true)
    {
        $this->nameserver  = $nameserver;
        $this->port        = $port;
        $this->timeout     = $timeout;
        $this->udp         = $udp;
        $this->tcpFallback = $tcpFallback;
    }

    public function resolveA(string $domain, bool $ip4only = false): array
    {
        $records = $this->dns_get_record($domain, "A");

        if (!$ip4only) {
            $ip6 = $this->dns_get_record($domain, "AAAA");
            if ($ip6) {
                $records = array_merge($records, $ip6);
            }
        }

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

    public function resolveMx(string $domain): array
    {
        $records = $this->dns_get_record($domain, "MX");
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

        $revs = array_map(function ($e) {
            return $e['target'];
        }, $this->dns_get_record($revIp, "PTR"));

        return $revs;
    }

    public function resolveTXT(string $domain): array
    {
        $records = $this->dns_get_record($domain, "TXT");
        if (false === $records) {
            throw new DNSLookupException;
        }

        $texts = [];

        foreach ($records as $record) {
            if ($record['type'] === "TXT") {
                $texts[] = $record['txt'];
            }
        }

        return $texts;
    }

    protected function dns_get_record($question, $type): array
    {
        $response = array();

        $dnsquery = new DNSQuery($this->nameserver, $this->port, $this->timeout, $this->udp, false, false);
        $result   = $dnsquery->query($question, $type);

        // Retry if we get a too big for UDP error
        if ($this->udp && $this->tcpFallback && $dnsquery->hasError() && $dnsquery->getLasterror() == "Response too big for UDP, retry with TCP") {
            $dnsquery = new DNSQuery($this->nameserver, $this->port, $this->timeout, false, false, false);
            $result   = $dnsquery->query($question, $type);
        }

        if ($dnsquery->hasError()) {
            throw new DNSLookupException($dnsquery->getLasterror());
        }

        foreach ($result as $record) {

            $extras = array();

            // additional data
            if (count($record->getExtras()) > 0) {
                foreach ($record->getExtras() as $key => $val) {
                    // We don't want to echo binary data
                    if ($key != 'ipbin') {
                        $extras[$key] = $val;
                    }
                }
            }

            switch ($type) {
                default:
                    throw new \Exception("Unsupported type ".$type.".");
                case "A":
                    $response[] = array(
                        "host"  => $record->getDomain(),
                        "class" => "IN",
                        "ttl"   => $record->getTtl(),
                        "type"  => $record->getTypeid(),
                        "ip"    => $record->getData(),
                    );
                    break;
                case "AAAA":
                    $response[] = array(
                        "host"  => $record->getDomain(),
                        "class" => "IN",
                        "ttl"   => $record->getTtl(),
                        "type"  => $record->getTypeid(),
                        "ipv6"  => $record->getData(),
                    );
                    break;
                case "MX":
                    $response[] = array(
                        "host"   => $record->getDomain(),
                        "class"  => "IN",
                        "ttl"    => $record->getTtl(),
                        "type"   => $record->getTypeid(),
                        "pri"    => $extras["level"],
                        "target" => $record->getData(),
                    );
                    break;
                case "TXT":
                    $response[] = array(
                        "host"    => $record->getDomain(),
                        "class"   => "IN",
                        "ttl"     => $record->getTtl(),
                        "type"    => $record->getTypeid(),
                        "txt"     => $record->getData(),
                        "entries" => array($record->getData()),
                    );
                    break;
                case "PTR":
                    $response[] = array(
                        "host"   => $record->getDomain(),
                        "class"  => "IN",
                        "ttl"    => $record->getTtl(),
                        "type"   => $record->getTypeid(),
                        "target" => $record->getData(),
                    );
                    break;
            }

        }

        return $response;
    }
}
