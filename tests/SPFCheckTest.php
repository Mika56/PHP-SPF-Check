<?php

namespace Mika56\SPFCheck\Test;


use Mika56\SPFCheck\Model\Result;
use Mika56\SPFCheck\SPFCheck;
use PHPUnit\Framework\TestCase;

class SPFCheckTest extends TestCase
{
    protected SPFCheck $SPFCheck;

    protected function setUp(): void
    {
        $this->SPFCheck = new SPFCheck(new DNSRecordGetterFixture());
        parent::setUp();
    }

    /**
     * @dataProvider dataProvider
     * @param $expectedResult
     * @param $domain
     * @param $ipAddress
     */
    public function testIsIpAllowed($expectedResult, $domain, $ipAddress)
    {
        $this->assertEquals($expectedResult, $this->SPFCheck->getIPStringResult($ipAddress, $domain));
    }

    public function dataProvider()
    {
        return [
            /* IP */
            [Result::SHORT_PASS, 'test.com', '127.0.0.1'],
            [Result::SHORT_PASS, 'test.com', '172.16.0.1'],
            [Result::SHORT_PASS, 'test.com', '192.168.0.1'],
            [Result::SHORT_PASS, 'test.com', 'fe80::8a2e:370:7334'],
            [Result::SHORT_FAIL, 'test.com', '8.8.8.8'],
            [Result::SHORT_PASS, 'test4nocidr.com', '127.0.0.1'],
            [Result::SHORT_FAIL, 'test4nocidr.com', '127.0.0.2'],
            [Result::SHORT_PASS, 'test6nocidr.com', 'fe80::'],
            [Result::SHORT_FAIL, 'test6nocidr.com', 'fe80::1'],

            /* A */
            [Result::SHORT_PASS, 'testa.com', '192.168.0.1'],
            [Result::SHORT_PASS, 'testa.com', '192.168.0.254'],
            [Result::SHORT_PASS, 'testadomcidr.com', '172.16.0.1'],
            [Result::SHORT_PASS, 'testadomcidr.com', '172.16.0.2'],
            [Result::SHORT_FAIL, 'testadomcidr.com', '172.16.1.2'],

            /* MX */
            [Result::SHORT_PASS, 'testmx.com', '192.168.0.1'],
            [Result::SHORT_PASS, 'testmx.com', '192.168.0.2'],
            [Result::SHORT_PASS, 'testmx2.com', '192.168.0.1'],
            [Result::SHORT_PASS, 'testmx3.com', '192.168.1.1'],
            [Result::SHORT_PASS, 'testmx3.com', '192.168.1.2'],
            [Result::SHORT_FAIL, 'testmx3.com', '192.168.2.2'],
            [Result::SHORT_PASS, 'testmx4.com', '192.168.0.1'],
            [Result::SHORT_PASS, 'testmx4.com', '192.168.0.2'],
            [Result::SHORT_PASS, 'testmx4.com', '172.16.0.1'],
            [Result::SHORT_PASS, 'testmx4.com', '172.16.0.2'],
            [Result::SHORT_FAIL, 'testmx4.com', '127.0.0.1'],

            /* PTR */
            [Result::SHORT_PASS, 'testptr.com', '127.0.0.1'],
            [Result::SHORT_PASS, 'testptrother.com', '8.8.8.8'],
            [Result::SHORT_FAIL, 'testptrother.com', '172.16.0.1'],

            /* Include */
            [Result::SHORT_PASS, 'testinclude.com', '192.168.0.1'],
            [Result::SHORT_FAIL, 'testinclude.com', '10.14.40.1'],

            /* No SPF */
            [Result::SHORT_NONE, 'testnospf.com', '8.8.8.8'],

            /* Non-existent domain */
            [Result::SHORT_TEMPERROR, 'testnonexistant.com', '8.8.8.8'],

            /* Neutral */
            [Result::SHORT_NEUTRAL, 'testneutral.com', '8.8.8.8'],

            /* Exists */
            [Result::SHORT_PASS, 'testexists.com', '8.8.8.8'],
            [Result::SHORT_FAIL, 'testnonexists.com', '8.8.8.8'],

            /* Invalid (permerror) */
            [Result::SHORT_PERMERROR, 'testinvalid.com', '8.8.8.8'],

            /* No domain */
            [Result::SHORT_NONE, '', '8.8.8.8'],
        ];
    }
}
