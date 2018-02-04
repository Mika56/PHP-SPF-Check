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
    protected $requestMXCount = 0;
    protected $requestPTRCount = 0;

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