<?php
/**
 * DNSRecordGetterDirect
 *
 * @author    Brian Tafoya <btafoya@briantafoya.com>
 */

namespace Mika56\SPFCheck;

use Mika56\SPFCheck\Exception\DNSLookupException;
use Mika56\SPFCheck\Exception\DNSLookupLimitReachedException;
use PurplePixie\PhpDns\DNSQuery;

class DNSRecordGetterDirect implements DNSRecordGetterInterface
{

    protected $requestCount = 0;
    protected $requestMXCount = 0;
    protected $requestPTRCount = 0;
    protected $nameserver = "8.8.8.8";
    protected $port = 53;
    protected $timeout = 30;
    protected $udp = true;
    protected $tcpFallback;

    const DNS_A = 'A';
    const DNS_CNAME = "CNAME";
    const DNS_HINFO = "HINFO";
    const DNS_CAA = "CAA";
    const DNS_MX = "MX";
    const DNS_NS = "NS";
    const DNS_PTR = "PTR";
    const DNS_SOA = "SOA";
    const DNS_TXT = "TXT";
    const DNS_AAAA = "AAAA";
    const DNS_SRV = "SRV";
    const DNS_NAPTR = "NAPTR";
    const DNS_A6 = "A6";
    const DNS_ALL = "ALL";
    const DNS_ANY = "ANY";

    /**
     * DNSRecordGetter constructor.
     *
     * @param string $nameserver
     * @param int $port
     * @param int $timeout
     * @param bool $udp
     * @param bool $tcpFallback
     */
    public function __construct($nameserver = "8.8.8.8", $port = 53, $timeout = 30, $udp = true, $tcpFallback = true)
    {
        $this->nameserver  = $nameserver;
        $this->port        = $port;
        $this->timeout     = $timeout;
        $this->udp         = $udp;
        $this->tcpFallback = $tcpFallback;
    }

    /**
     * @param $domain string The domain to get SPF record
     * @return string[] The SPF record(s)
     * @throws DNSLookupException
     */
    public function getSPFRecordForDomain($domain)
    {
        $records = $this->dns_get_record($domain, "TXT");
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

    public function resolveA($domain, $ip4only = false)
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

    public function resolveMx($domain)
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
        }, $this->dns_get_record($revIp, "PTR"));

        return $revs;
    }

    public function exists($domain)
    {
        try {
            return count($this->resolveA($domain, true)) > 0;
        } catch (DNSLookupException $e) {
            return false;
        }
    }

    public function dns_get_record($question, $type)
    {
        $response = array();

        $dnsquery = new DNSQuery($this->nameserver, (int)$this->port, (int)$this->timeout, $this->udp, false, false);
        $result   = $dnsquery->query($question, $type);

        // Retry if we get an too big for UDP error
        if ($this->udp && $this->tcpFallback && $dnsquery->hasError() && $dnsquery->getLasterror() == "Response too big for UDP, retry with TCP") {
            $dnsquery = new DNSQuery($this->nameserver, (int)$this->port, (int)$this->timeout, false, false, false);
            $result   = $dnsquery->query($question, $type);
        }

        if ($dnsquery->hasError()) {
            throw new DNSLookupException($dnsquery->getLasterror());
        }

        foreach ($result as $index => $record) {

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
                    break;
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

    /**
     * @codeCoverageIgnore
     */
    public function resetRequestCount()
    {
        trigger_error('DNSRecordGetterInterface::resetRequestCount() is deprecated. Please use resetRequestCounts() instead', E_USER_DEPRECATED);
        $this->resetRequestCounts();
    }

    public function countRequest()
    {
        if (++$this->requestCount > 10) {
            throw new DNSLookupLimitReachedException();
        }
    }

    public function resetRequestCounts()
    {
        $this->requestCount    = 0;
        $this->requestMXCount  = 0;
        $this->requestPTRCount = 0;
    }

    public function countMxRequest()
    {
        if (++$this->requestMXCount > 10) {
            throw new DNSLookupLimitReachedException();
        }
    }

    public function countPtrRequest()
    {
        if (++$this->requestPTRCount > 10) {
            throw new DNSLookupLimitReachedException();
        }
    }
}
