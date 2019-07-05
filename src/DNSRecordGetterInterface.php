<?php
/**
 *
 * @author Mikael Peigney
 */

namespace Mika56\SPFCheck;


use Mika56\SPFCheck\Exception\DNSLookupException;
use Mika56\SPFCheck\Exception\DNSLookupLimitReachedException;

interface DNSRecordGetterInterface
{
    /**
     * @param $domain
     * @return string[]
     * @throws DNSLookupException
     */
    public function getSPFRecordForDomain($domain);

    public function resolveA($domain, $ip4only = false);

    public function resolveMx($domain);

    public function resolvePtr($ipAddress);

    /**
     * @param $domain
     * @return boolean
     * @throws DNSLookupException
     */
    public function exists($domain);

    /**
     * @return void
     * @deprecated {@see resetRequestCounts}
     * @codeCoverageIgnore
     */
    public function resetRequestCount();

    /**
     * Reset all request counters (A/AAAA, MX, PTR)
     * @return void
     */
    public function resetRequestCounts();

    /**
     * Count a A/AAAA request
     * @throws DNSLookupLimitReachedException
     * @return void
     */
    public function countRequest();

    /**
     * Count an MX request
     * @throws DNSLookupLimitReachedException
     * @return void
     */
    public function countMxRequest();

    /**
     * Count a PTR request
     * @throws DNSLookupLimitReachedException
     * @return void
     */
    public function countPtrRequest();
}