<?php
/**
 * DNSRecordGetterDirectTest - phpUnit Test
 *
 * @author    Brian Tafoya <btafoya@briantafoya.com>
 */
declare(strict_types=1);

namespace Mika56\SPFCheck;

/**
 * @covers \Mika56\SPFCheck\DNSRecordGetterDirect
 */
class DNSRecordGetterDirectTest extends \PHPUnit_Framework_TestCase
{
    private $dnsServer = '127.0.0.1';

    public function __construct($name = null, array $data = array(), $dataName = '')
    {
        parent::__construct($name, $data, $dataName);
        if (array_key_exists('DNS_SERVER', $_ENV)) {
            $this->dnsServer = $_ENV['DNS_SERVER'];
        }
    }

    public function setUp()
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
        $dnsRecordGetter = new DNSRecordGetterDirect($this->dnsServer, 53, 3, false);

        $result = $dnsRecordGetter->getSPFRecordForDomain('test.local.dev');
        $this->assertCount(1, $result);
        $this->assertContains('v=spf1 a -all', $result);

        $result = $dnsRecordGetter->getSPFRecordForDomain('noexist.local.dev');
        $this->assertEmpty($result);
    }

    public function testResolveMx()
    {
        $dnsRecordGetter = new DNSRecordGetterDirect($this->dnsServer);

        $result = $dnsRecordGetter->resolveMx('test.local.dev');
        $this->assertCount(1, $result);
        $this->assertContains('smtp.test.local.dev', $result);

        $result = $dnsRecordGetter->resolveMx('noexist.local.dev');
        $this->assertCount(0, $result);
    }

    public function tearDown()
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
