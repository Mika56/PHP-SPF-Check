<?php
/**
 *
 * @author Mikael Peigney
 */

namespace Mika56\SPFCheck;


class SPFCheckTest extends \PHPUnit_Framework_TestCase
{
    /** @var  SPFCheck */
    protected $SPFCheck;

    protected function setUp()
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
        $this->assertEquals($expectedResult, $this->SPFCheck->isIPAllowed($ipAddress, $domain));
    }

    public function dataProvider()
    {
        return [
            /* IP */
            [SPFCheck::RESULT_PASS, 'test.com', '127.0.0.1'],
            [SPFCheck::RESULT_PASS, 'test.com', '172.16.0.1'],
            [SPFCheck::RESULT_PASS, 'test.com', '192.168.0.1'],
            [SPFCheck::RESULT_PASS, 'test.com', 'fe80::8a2e:370:7334'],
            [SPFCheck::RESULT_FAIL, 'test.com', '8.8.8.8'],
            [SPFCheck::RESULT_PASS, 'test4nocidr.com', '127.0.0.1'],
            [SPFCheck::RESULT_FAIL, 'test4nocidr.com', '127.0.0.2'],
            [SPFCheck::RESULT_PASS, 'test6nocidr.com', 'fe80::'],
            [SPFCheck::RESULT_FAIL, 'test6nocidr.com', 'fe80::1'],

            /* A */
            [SPFCheck::RESULT_PASS, 'testa.com', '192.168.0.1'],
            [SPFCheck::RESULT_PASS, 'testa.com', '192.168.0.254'],
            [SPFCheck::RESULT_PASS, 'testadomcidr.com', '172.16.0.1'],
            [SPFCheck::RESULT_PASS, 'testadomcidr.com', '172.16.0.2'],
            [SPFCheck::RESULT_FAIL, 'testadomcidr.com', '172.16.1.2'],

            /* MX */
            [SPFCheck::RESULT_PASS, 'testmx.com', '192.168.0.1'],
            [SPFCheck::RESULT_PASS, 'testmx.com', '192.168.0.2'],
            [SPFCheck::RESULT_PASS, 'testmx2.com', '192.168.0.1'],
            [SPFCheck::RESULT_PASS, 'testmx3.com', '192.168.1.1'],
            [SPFCheck::RESULT_PASS, 'testmx3.com', '192.168.1.2'],
            [SPFCheck::RESULT_FAIL, 'testmx3.com', '192.168.2.2'],
            [SPFCheck::RESULT_PASS, 'testmx4.com', '192.168.0.1'],
            [SPFCheck::RESULT_PASS, 'testmx4.com', '192.168.0.2'],
            [SPFCheck::RESULT_PASS, 'testmx4.com', '172.16.0.1'],
            [SPFCheck::RESULT_PASS, 'testmx4.com', '172.16.0.2'],
            [SPFCheck::RESULT_FAIL, 'testmx4.com', '127.0.0.1'],

            /* PTR */
            [SPFCheck::RESULT_PASS, 'testptr.com', '127.0.0.1'],
            [SPFCheck::RESULT_PASS, 'testptrother.com', '8.8.8.8'],
            [SPFCheck::RESULT_FAIL, 'testptrother.com', '172.16.0.1'],

            /* Include */
            [SPFCheck::RESULT_PASS, 'testinclude.com', '192.168.0.1'],
            [SPFCheck::RESULT_FAIL, 'testinclude.com', '10.14.40.1'],

            /* No SPF */
            [SPFCheck::RESULT_NONE, 'testnospf.com', '8.8.8.8'],

            /* Non-existent domain */
            [SPFCheck::RESULT_TEMPERROR, 'testnonexistant.com', '8.8.8.8'],

            /* Neutral */
            [SPFCheck::RESULT_NEUTRAL, 'testneutral.com', '8.8.8.8'],

            /* Exists */
            [SPFCheck::RESULT_PASS, 'testexists.com', '8.8.8.8'],
            [SPFCheck::RESULT_FAIL, 'testnonexists.com', '8.8.8.8'],

            /* Invalid (permerror) */
            [SPFCheck::RESULT_PERMERROR, 'testinvalid.com', '8.8.8.8'],

            /* No domain */
            [SPFCheck::RESULT_NONE, '', '8.8.8.8'],
        ];
    }
}
