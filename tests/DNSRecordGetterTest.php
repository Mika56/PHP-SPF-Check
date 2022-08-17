<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\Test;


use Mika56\SPFCheck\DNSRecordGetter;
use Mika56\SPFCheck\Exception\DNSLookupLimitReachedException;
use PHPUnit\Framework\TestCase;
use Symfony\Bridge\PhpUnit\DnsMock;

class DNSRecordGetterTest extends TestCase
{
    public function testGetSPFRecordForDomain()
    {
        DnsMock::withMockedHosts([
            'example.com'  => [
                [
                    'type' => 'TXT',
                    'txt'  => 'v=spf1 a',
                ],
            ],
            'example2.com' => [
                [
                    'type' => 'TXT',
                    'txt'  => 'v=spf1',
                ],
            ],
            'example3.com' => [
                [
                    'type' => 'TXT',
                    'txt'  => 'v=spf2',
                ],
            ],
        ]);

        $dnsRecordGetter = new DNSRecordGetter();

        $result = $dnsRecordGetter->getSPFRecordForDomain('example.com');
        $this->assertCount(1, $result);
        $this->assertContains('v=spf1 a', $result);

        $result = $dnsRecordGetter->getSPFRecordForDomain('example2.com');
        $this->assertCount(1, $result);
        $this->assertContains('v=spf1', $result);

        $result = $dnsRecordGetter->getSPFRecordForDomain('example3.com');
        $this->assertEmpty($result);
    }

    public function testResolveA()
    {
        DnsMock::withMockedHosts([
            'example.com' => [
                [
                    'type' => 'A',
                    'ip'   => '1.2.3.4',
                ],
                [
                    'type' => 'AAAA',
                    'ipv6' => '::12',
                ],
            ],
        ]);

        $dnsRecordGetter = new DNSRecordGetter();

        $result = $dnsRecordGetter->resolveA('example.com', true);
        $this->assertContains('1.2.3.4', $result);
        $this->assertNotContains('::12', $result);

        $result = $dnsRecordGetter->resolveA('example.com', false);
        $this->assertContains('1.2.3.4', $result);
        $this->assertContains('::12', $result);
    }

    public function testResolveMx()
    {
        DnsMock::withMockedHosts([
            'example.com'  => [
                [
                    'type'   => 'MX',
                    'pri'    => 10,
                    'target' => 'mail.example.com',
                ],
            ],
            'example2.com' => [],
        ]);

        $dnsRecordGetter = new DNSRecordGetter();

        $result = $dnsRecordGetter->resolveMx('example.com');
        $this->assertCount(1, $result);
        $this->assertContains('mail.example.com', $result);

        $result = $dnsRecordGetter->resolveMx('example2.com');
        $this->assertCount(0, $result);
    }

    public function testResolvePtrIpv4()
    {
        DnsMock::withMockedHosts([
            '1.0.0.127.in-addr.arpa' => [
                [
                    'type'   => 'PTR',
                    'target' => 'example.com',
                ],
            ],
        ]);

        $dnsRecordGetter = new DNSRecordGetter();

        $result = $dnsRecordGetter->resolvePtr('127.0.0.1');
        $this->assertCount(1, $result);
        $this->assertContains('example.com', $result);
    }

    public function testResolvePtrIpv6()
    {
        DnsMock::withMockedHosts([
            '0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa' => [
                [
                    'type'   => 'PTR',
                    'target' => 'example.com',
                ],
            ],
        ]);

        $dnsRecordGetter = new DNSRecordGetter();

        $result = $dnsRecordGetter->resolvePtr('fe80::');
        $this->assertCount(1, $result);
        $this->assertContains('example.com', $result);
    }

    public function testExists()
    {
        DnsMock::withMockedHosts([
            'example.com' => [
                [
                    'type' => 'A',
                    'ip'   => '127.0.0.1',
                ],
            ],
        ]);

        $dnsRecordGetter = new DNSRecordGetter();
        $this->assertTrue($dnsRecordGetter->exists('example.com'));
        $this->assertFalse($dnsRecordGetter->exists('example2.com'));
    }

    public function testLookupLimitEdge()
    {
        $dnsRecordGetter = new DNSRecordGetter();
        for ($i = 0; $i < 10; $i++) {
            $dnsRecordGetter->countRequest();
        }
    }

    public function testLookupLimitExceed()
    {
        $this->expectException(DNSLookupLimitReachedException::class);
        $dnsRecordGetter = new DNSRecordGetter();
        for ($i = 0; $i <= 10; $i++) {
            $dnsRecordGetter->countRequest();
        }
    }

    public function testLookupLimitReset()
    {
        $dnsRecordGetter = new DNSRecordGetter();
        for ($i = 0; $i < 10; $i++) {
            $dnsRecordGetter->countRequest();
        }
        $dnsRecordGetter->resetRequestCounts();
        for ($i = 0; $i < 10; $i++) {
            $dnsRecordGetter->countRequest();
        }
    }

    public function testMXLookupLimitEdge()
    {
        $dnsRecordGetter = new DNSRecordGetter();
        for ($i = 0; $i < 10; $i++) {
            $dnsRecordGetter->countMxRequest();
        }
    }

    public function testMXLookupLimitExceed()
    {
        $this->expectException(DNSLookupLimitReachedException::class);
        $dnsRecordGetter = new DNSRecordGetter();
        for ($i = 0; $i <= 10; $i++) {
            $dnsRecordGetter->countMxRequest();
        }
    }

    public function testMXLookupLimitReset()
    {
        $dnsRecordGetter = new DNSRecordGetter();
        for ($i = 0; $i < 10; $i++) {
            $dnsRecordGetter->countMxRequest();
        }
        $dnsRecordGetter->resetRequestCounts();
        for ($i = 0; $i < 10; $i++) {
            $dnsRecordGetter->countMxRequest();
        }
    }

    public function testPTRLookupLimitEdge()
    {
        $dnsRecordGetter = new DNSRecordGetter();
        for ($i = 0; $i < 10; $i++) {
            $dnsRecordGetter->countPtrRequest();
        }
    }

    public function testPTRLookupLimitExceed()
    {
        $this->expectException(DNSLookupLimitReachedException::class);
        $dnsRecordGetter = new DNSRecordGetter();
        for ($i = 0; $i <= 10; $i++) {
            $dnsRecordGetter->countPtrRequest();
        }
    }

    public function testPTRLookupLimitReset()
    {
        $dnsRecordGetter = new DNSRecordGetter();
        for ($i = 0; $i < 10; $i++) {
            $dnsRecordGetter->countPtrRequest();
        }
        $dnsRecordGetter->resetRequestCounts();
        for ($i = 0; $i < 10; $i++) {
            $dnsRecordGetter->countPtrRequest();
        }
    }

}
