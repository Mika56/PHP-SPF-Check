<?php
/**
 *
 * @author Mikael Peigney
 */
namespace Mika56\SPFCheck;

class RFC4408Test extends OpenSPFTest
{
    /**
     * @dataProvider RFC4408DataProvider
     */
    public function testRFC4408($ipAddress, $domain, DNSRecordGetterInterface $dnsData, $expectedResult)
    {
        $spfCheck = new SPFCheck($dnsData);
        $result   = $spfCheck->isIPAllowed($ipAddress, $domain);
        $this->assertTrue(
            in_array($result, $expectedResult),
            'Failed asserting that (expected) '.(
            (count($expectedResult) == 1)
                ? ($expectedResult[0].' equals ')
                : ('('.implode(', ', $expectedResult).') contains '))
            .'(result) '.$result
        );
    }

    public function RFC4408DataProvider()
    {
        $scenarios = file_get_contents('http://www.openspf.org/svn/project/test-suite/rfc4408-tests.yml');

        return $this->loadTestCases($scenarios);
    }

    function isScenarioAllowed($scenarioName)
    {
        return $scenarioName != 'Macro expansion rules';
    }

    function isTestAllowed($testName)
    {
        $ignored_tests = array(
            // @formatter:off
            'a-cidr6-0-ip4', 'a-cidr6-0-ip4mapped', 'a-cidr6-0-ip6', 'a-cidr6-0-nxdomain',     // Dual CIDR is not (yet) supported
            'mx-cidr6-0-ip4', 'mx-cidr6-0-ip4mapped', 'mx-cidr6-0-ip6', 'mx-cidr6-0-nxdomain', // Dual CIDR is not (yet) supported
            'a-dual-cidr-ip4-match', 'a-dual-cidr-ip6-match', 'a-dual-cidr-ip6-default', 'a-cidr4-0-ip6', 'mx-cidr4-0-ip6', // Dual CIDR is not (yet) supported
            // @formatter:on
        );

        return !in_array($testName, $ignored_tests);
    }

    function fixZoneData($scenarioName, $zoneData)
    {
        if ($scenarioName == 'IP6 mechanism syntax') {
            // This syntax is deprecated and not supported by this library
            $zoneData['e2.example.com'][0]['SPF'] = 'v=spf1 ip6:::FFFF:1.1.1.1/0';
            $zoneData['e3.example.com'][0]['SPF'] = 'v=spf1 ip6:::FFFF:1.1.1.1/129';
            $zoneData['e4.example.com'][0]['SPF'] = 'v=spf1 ip6:::FFFF:1.1.1.1//33';
        }

        return $zoneData;
    }
}