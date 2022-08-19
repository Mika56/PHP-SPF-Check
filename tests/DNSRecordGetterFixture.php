<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\Test;


use Mika56\SPFCheck\DNS\DNSRecordGetterInterface;
use Mika56\SPFCheck\Exception\DNSLookupException;

class DNSRecordGetterFixture implements DNSRecordGetterInterface
{

    protected array $spfRecords = [
        'test.com'          => 'v=spf1 +ip4:127.0.0.0/8 +ip4:172.16.0.0/16 ip4:192.168.0.0/24 +ip6:fe80::/64 -all',
        'testa.com'         => 'v=spf1 +a +a/24 +a:testa2.com +a:testa2.com/24 -all',
        'testmx.com'        => 'v=spf1 +mx:testmx2.com/24 -all',
        'testmx2.com'       => 'v=spf1 +mx -all',
        'testmx3.com'       => 'v=spf1 +mx/24 -all',
        'testnospf.com'     => '',
        'testneutral.com'   => 'v=spf1 +a',
        'test4nocidr.com'   => 'v=spf1 +ip4:127.0.0.1 -all',
        'test6nocidr.com'   => 'v=spf1 +ip6:fe80:: -all',
        'testadomcidr.com'  => 'v=spf1 +a:testa2.com/24 -all',
        'testmx4.com'       => 'v=spf1 +mx:testmx.com/24 -all',
        'testinvalid.com'   => 'v=spf1 +hey -all',
        'testexists.com'    => 'v=spf1 exists:test.com -all',
        'testnonexists.com' => 'v=spf1 exists:thetest.com -all',
        'testptr.com'       => 'v=spf1 ptr -all',
        'testptrother.com'  => 'v=spf1 ptr:otherptr.com -all',
        'testinclude.com'   => 'v=spf1 include:test.com -all',
    ];

    protected array $aRecords = [
        'test.com'         => ['127.0.0.1', '192.168.0.1', 'fe80::'],
        'testa.com'        => ['192.168.0.1'],
        'testa2.com'       => ['172.16.0.1'],
        'mail.testmx.com'  => ['192.168.0.1'],
        'mail2.testmx.com' => ['172.16.0.1'],
        'testptr.com'      => ['127.0.0.1'],
        'otherptr.com'     => ['8.8.8.8'],
    ];

    protected array $mxRecords = [ // MX can be a domain name or an IP address (even though it is not recommended)
        'testmx.com'  => ['mail.testmx.com', 'mail2.testmx.com'],
        'testmx2.com' => ['192.168.0.1'],
        'testmx3.com' => ['192.168.1.1'],
    ];

    protected array $ptrRecords = [
        '127.0.0.1' => ['testptr.com'],
        '8.8.8.8'   => ['otherptr.com'],
    ];

    public function getSPFRecordsForDomain(string $domain): array
    {
        if (array_key_exists($domain, $this->spfRecords)) {
            if ($this->spfRecords[$domain] == '') {
                return array();
            }

            return array($this->spfRecords[$domain]);
        }

        throw new DNSLookupException;
    }

    public function resolveA(string $domain, $ip4only = false): array
    {
        if (array_key_exists($domain, $this->aRecords)) {
            return $this->aRecords[$domain];
        }

        return array();
    }

    public function resolveMx(string $domain): array
    {
        if (array_key_exists($domain, $this->mxRecords)) {
            return $this->mxRecords[$domain];
        }

        return array();
    }

    public function resolvePtr(string $ipAddress): array
    {
        if (array_key_exists($ipAddress, $this->ptrRecords)) {
            return $this->ptrRecords[$ipAddress];
        }

        return array();
    }
}
