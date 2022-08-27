<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\Test;


use Mika56\SPFCheck\DNS\DNSRecordGetter;
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
        ]);

        $dnsRecordGetter = new DNSRecordGetter();

        $result = $dnsRecordGetter->resolveTXT('example.com');
        $this->assertCount(1, $result);
        $this->assertContains('v=spf1 a', $result);

        $result = $dnsRecordGetter->resolveTXT('example2.com');
        $this->assertCount(1, $result);
        $this->assertContains('v=spf1', $result);
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

}
