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
        $this->requestCount = 0;
    }

    public function countRequest()
    {
        if (++$this->requestCount == 10) {
            throw new DNSLookupLimitReachedException();
        }
    }
}