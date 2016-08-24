<?php
/**
 *
 * @author Mikael Peigney
 */

namespace Mika56\SPFCheck;


use Mika56\SPFCheck\Exception\DNSLookupLimitReachedException;

class DNSRecordGetterIssue7 implements DNSRecordGetterInterface
{
    protected $requestCount = 0;

    protected $spfRecords = [
    ];

    public function getSPFRecordForDomain($domain)
    {
        return array();
    }

    public function resolveA($domain, $ip4only = false)
    {
    }

    public function resolveMx($domain)
    {
    }

    public function resolvePtr($ipAddress)
    {
    }

    public function exists($domain)
    {
    }

    public function resetRequestCount()
    {
        $this->requestCount = 0;
    }

    public function countRequest()
    {
        if (++$this->requestCount == 10) {
            throw new DNSLookupLimitReachedException();
        }
    }
}