<?php
/**
 *
 * @author Mikael Peigney
 */

namespace Mika56\SPFCheck;


use Mika56\SPFCheck\Exception\DNSLookupException;
use Mika56\SPFCheck\Exception\DNSLookupLimitReachedException;

class DNSRecordGetterIssue3 implements DNSRecordGetterInterface
{
    protected $requestCount = 0;
    protected $requestMXCount = 0;
    protected $requestPTRCount = 0;

    protected $spfRecords = [
        'domain.com' => 'v=spf1 include:domain.com ~all',
    ];

    public function getSPFRecordForDomain($domain)
    {
        if (array_key_exists($domain, $this->spfRecords)) {
            if ($this->spfRecords[$domain] == '') {
                return false;
            }

            return array($this->spfRecords[$domain]);
        }

        throw new DNSLookupException;
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