<?php
/**
 *
 * @author Mikael Peigney
 */

namespace Mika56\SPFCheck;

/**
 * This tests ensures that when a DNS query fails with UDP, it is retried with TCP
 * TXT records might be too long to fit inside an UDP packet
 */
class Pull34Test extends \PHPUnit_Framework_TestCase
{
    private $dnsServer = '127.0.0.1';
    private $zonesToCreate = [
        'myloooooooooooooooooooooooooooooooooongfirstprovider.com',
        'myloooooooooooooooooooooooooooooooooongsecondprovider.com',
        'myloooooooooooooooooooooooooooooooooongthirdprovider.com',
        'myloooooooooooooooooooooooooooooooooongfourthprovider.com',
        'myloooooooooooooooooooooooooooooooooongfifthprovider.com',
        'myloooooooooooooooooooooooooooooooooongsixthprovider.com',
        'myloooooooooooooooooooooooooooooooooongseventhprovider.com',
        'myloooooooooooooooooooooooooooooooooongeightprovider.com',
        'myloooooooooooooooooooooooooooooooooongninthprovider.com',
    ];

    public function __construct($name = null, array $data = array(), $dataName = '')
    {
        parent::__construct($name, $data, $dataName);
        if (array_key_exists('DNS_SERVER', $_ENV)) {
            $this->dnsServer = $_ENV['DNS_SERVER'];
        }
    }

    public function testPull34()
    {
        // UDP with TCP fallback
        $dnsRecordGetter = new DNSRecordGetterDirect($this->dnsServer, 53, 3);
        $SPFCheck        = new SPFCheck($dnsRecordGetter);
        $this->assertEquals(SPFCheck::RESULT_PASS, $SPFCheck->isIPAllowed('127.0.0.1', 'test.local.dev'));

        // TCP only
        $dnsRecordGetter = new DNSRecordGetterDirect($this->dnsServer, 53, 3, false);
        $SPFCheck        = new SPFCheck($dnsRecordGetter);
        $this->assertEquals(SPFCheck::RESULT_PASS, $SPFCheck->isIPAllowed('127.0.0.1', 'test.local.dev'));

        // UDP only
        $dnsRecordGetter = new DNSRecordGetterDirect($this->dnsServer, 53, 3, true, false);
        $SPFCheck        = new SPFCheck($dnsRecordGetter);
        $this->assertEquals(SPFCheck::RESULT_TEMPERROR, $SPFCheck->isIPAllowed('127.0.0.1', 'test.local.dev'));
    }

    public function setUp()
    {
        // Ensure DNS server has no entries
        $this->tearDown();

        foreach ($this->zonesToCreate as $zone) {
            $this->createZone($zone);
        }
        $this->createZone('test.local.dev');

        $postdata = [
            'rrsets' => [
                [
                    'name'       => 'test.local.dev',
                    'type'       => 'TXT',
                    'ttl'        => 86400,
                    'changetype' => 'REPLACE',
                    'records'    => [
                        [
                            'content'  => '"v=spf1 a ip4:10.0.0.0/8 include='.implode(' include=', $this->zonesToCreate).' ip4:127.0.0.1 -all"',
                            'disabled' => false,
                            'name'     => 'test.local.dev',
                            'type'     => 'TXT',
                            'ttl'      => 86400,
                            'priority' => 1,
                        ],
                    ],
                ],
            ],
        ];

        $this->dnsApi('servers/localhost/zones/test.local.dev.', 'PATCH', $postdata);
    }

    public function tearDown()
    {
        foreach ($this->zonesToCreate as $zone) {
            @$this->dnsApi('servers/localhost/zones/'.$zone, 'DELETE');
        }
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

        return file_get_contents('http://'.$this->dnsServer.':80/'.$url, false, $context);
    }

    private function createZone($zone)
    {
        $postdata = [
            'name'        => $zone,
            'kind'        => 'Native',
            'masters'     => [],
            'nameservers' => ['ns1.'.$zone, 'ns2.'.$zone,],
        ];

        $this->dnsApi('servers/localhost/zones', 'POST', $postdata);

        if ($zone !== 'test.local.dev') {
            $postdata = [
                'rrsets' => [
                    [
                        'name'       => $zone,
                        'type'       => 'TXT',
                        'ttl'        => 86400,
                        'changetype' => 'REPLACE',
                        'records'    => [
                            [
                                'content'  => '"v=spf1 ?all"',
                                'disabled' => false,
                                'name'     => $zone,
                                'type'     => 'TXT',
                                'ttl'      => 86400,
                                'priority' => 1,
                            ],
                        ],
                    ],
                ],
            ];

            $this->dnsApi('servers/localhost/zones/'.$zone.'.', 'PATCH', $postdata);
        }
    }
}