<?php
/**
 * DNSRecordGetterDirectTest - phpUnit Test
 *
 * @author    Brian Tafoya <btafoya@briantafoya.com>
 */
declare(strict_types=1);

namespace Mika56\SPFCheck\Test;

use Mika56\SPFCheck\DNS\DNSRecordGetterDirect;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Mika56\SPFCheck\DNS\DNSRecordGetterDirect
 */
class DNSRecordGetterDirectTest extends TestCase
{
    private string $dnsServer = '127.0.0.1';
    private int $dnsServerPort = 53;

    public function __construct($name = null, array $data = array(), $dataName = '')
    {
        parent::__construct($name, $data, $dataName);
        if (array_key_exists('DNS_SERVER', $_ENV)) {
            $this->dnsServer = $_ENV['DNS_SERVER'];
        }
        if (array_key_exists('DNS_SERVER_PORT', $_ENV)) {
            $this->dnsServerPort = (int) $_ENV['DNS_SERVER_PORT'];
        }
    }

    public function setUp(): void
    {
        // Ensure DNS server has no entries
        $this->tearDown();

        $postdata = [
            'name'        => 'test.local.dev',
            'kind'        => 'Native',
            'masters'     => [],
            'nameservers' => ['ns1.test.local.dev', 'ns2.test.local.dev',],
        ];

        $this->dnsApi('servers/localhost/zones', 'POST', $postdata);

        $postdata = [
            'rrsets' => [
                [
                    'name'       => 'test.local.dev',
                    'type'       => 'TXT',
                    'ttl'        => 86400,
                    'changetype' => 'REPLACE',
                    'records'    => [
                        [
                            'content'  => '"notaspf"',
                            'disabled' => false,
                            'name'     => 'test.local.dev',
                            'type'     => 'TXT',
                            'ttl'      => 86400,
                            'priority' => 0,
                        ],
                        [
                            'content'  => '"v=spf1 a -all"',
                            'disabled' => false,
                            'name'     => 'test.local.dev',
                            'type'     => 'TXT',
                            'ttl'      => 86400,
                            'priority' => 1,
                        ],
                    ],
                ],
                [
                    'name'       => 'test.local.dev',
                    'type'       => 'MX',
                    'ttl'        => 86400,
                    'changetype' => 'REPLACE',
                    'records'    => [
                        [
                            'content'  => 'smtp.test.local.dev',
                            'disabled' => false,
                            'name'     => 'test.local.dev',
                            'type'     => 'MX',
                            'ttl'      => 86400,
                            'priority' => 0,
                        ],
                    ],
                ],
            ],
        ];

        $this->dnsApi('servers/localhost/zones/test.local.dev.', 'PATCH', $postdata);
    }

    public function testGetSPFRecordForDomain()
    {
        $dnsRecordGetter = new DNSRecordGetterDirect($this->dnsServer, $this->dnsServerPort, 3, false);

        $result = $dnsRecordGetter->resolveTXT('test.local.dev');
        $this->assertCount(2, $result);
        $this->assertContains('v=spf1 a -all', $result);

        $result = $dnsRecordGetter->resolveTXT('noexist.local.dev');
        $this->assertEmpty($result);
    }

    public function testResolveMx()
    {
        $dnsRecordGetter = new DNSRecordGetterDirect($this->dnsServer, $this->dnsServerPort);

        $result = $dnsRecordGetter->resolveMx('test.local.dev');
        $this->assertCount(1, $result);
        $this->assertContains('smtp.test.local.dev', $result);

        $result = $dnsRecordGetter->resolveMx('noexist.local.dev');
        $this->assertCount(0, $result);
    }

    public function tearDown(): void
    {
        @$this->dnsApi('servers/localhost/zones/test.local.dev', 'DELETE');
    }

    private function dnsApi($url, $method, $data = [])
    {
        $opts = [
            'http' => [
                'method'  => $method,
                'header'  => 'Content-type: application/json'."\r\n".'X-API-Key: password'."\r\n",
                'content' => json_encode($data),
            ],
        ];

        $context = stream_context_create($opts);

        file_get_contents('http://'.$this->dnsServer.':80/'.$url, false, $context);
    }
}
