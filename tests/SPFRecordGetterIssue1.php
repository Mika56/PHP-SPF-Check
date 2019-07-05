<?php
/**
 * Created by mikaelp on 4/26/2016 9:36 AM
 */

namespace Mika56\SPFCheck;


use Mika56\SPFCheck\Exception\DNSLookupException;

class DNSRecordGetterIssue1 implements DNSRecordGetterInterface
{
    protected $spfRecords = [
        'domaina.com' => 'v=spf1 include:domainb.com include:domainc.com -all',
        'domainb.com' => 'v=spf1 -all',
        'domainc.com' => 'v=spf1 +ip4:127.0.0.1 -all',
    ];

    protected $aRecords = [];

    protected $mxRecords = [];

    protected $ptrRecords = [];

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
        if (array_key_exists($domain, $this->aRecords)) {
            return $this->aRecords[$domain];
        }

        return false;
    }

    public function resolveMx($domain)
    {
        if (array_key_exists($domain, $this->mxRecords)) {
            return $this->mxRecords[$domain];
        }

        return false;
    }

    public function resolvePtr($ipAddress)
    {
        if (array_key_exists($ipAddress, $this->ptrRecords)) {
            return $this->ptrRecords[$ipAddress];
        }

        return false;
    }

    public function exists($domain)
    {
        return array_key_exists($domain, $this->aRecords) && count($this->aRecords) > 0;
    }

    public function resetRequestCount()
    {
    }

    public function countRequest()
    {
    }

    public function resetRequestCounts()
    {
    }

    public function countMxRequest()
    {
    }

    public function countPtrRequest()
    {
    }
}