<?php
/**
 *
 * @author Mikael Peigney
 */

namespace Mika56\SPFCheck;


interface DNSRecordGetterInterface
{
    public function getSPFRecordForDomain($domain);
    public function resolveA($domain, $ip4only = false);
    public function resolveMx($domain);
    public function resolvePtr($ipAddress);
    public function exists($domain);
    public function resetRequestCount();
    public function countRequest();
}