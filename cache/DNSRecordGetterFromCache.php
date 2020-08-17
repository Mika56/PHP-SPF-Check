<?php

namespace App;

use App\Models\SpfDnsCache;
use Mika56\SPFCheck\DNSRecordGetter;
use Mika56\SPFCheck\Exception\DNSLookupLimitReachedException;

/**
 * Cache implementation
 *
 * NOTE THIS NOT COMPLIANT WITH THE SPF STANDARD AS IT ALLOWS
 * MORE THAN 10 LOOKUPS.
 *
 * If you care, fix the max lookup variables below.
 *
 * Copyright 2020 Rob Thomas <xrobau@gmail.com>
 *
 * @licence MIT
 */

class DNSRecordGetterFromCache extends DNSRecordGetter
{
    private $maxmx = 20;
    private $maxptr = 20;
    private $maxrequest = 20;

    public function getSPFRecordForDomain($domain)
    {
        $cache = SpfDnsCache::getTxtRecords($domain);
        if ($cache['found']) {
            return $cache['records'];
        }

        // We don't have it cached, grab it from our parent
        $records = parent::getSPFRecordForDomain($domain);
        // If there's no records, only cache for 1 hour, otherwise cache for default
        if (!$records) {
            $expiry = new \DateInterval('PT1H');
        } else {
            $expiry = null;
        }
        SpfDnsCache::addEntry($domain, $records, false, $expiry);
        return $records;
    }

    public function countMxRequest()
    {
        if ($this->requestMXCount++ >= $this->maxmx) {
            throw new DNSLookupLimitReachedException();
        }
    }

    public function countPtrRequest()
    {
        if ($this->requestPTRCount++ >= $this->maxptr) {
            throw new DNSLookupLimitReachedException();
        }
    }
    public function countRequest()
    {
        if ($this->requestCount++ >= $this->maxrequest) {
            throw new DNSLookupLimitReachedException();
        }
    }
}
