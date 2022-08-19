<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\Test;

use Mika56\SPFCheck\DNS\DNSRecordGetterInterface;
use Mika56\SPFCheck\Exception\DNSLookupException;
use Mika56\SPFCheck\SPFCheck;

class RFC4408Test extends OpenSPFTest
{
    /**
     * @dataProvider RFC4408DataProvider
     */
    public function testRFC4408($ipAddress, $domain, DNSRecordGetterInterface $dnsData, $expectedResult)
    {
        $spfCheck = new SPFCheck($dnsData);
        $result = $spfCheck->getIPStringResult($ipAddress, $domain);

        try {
            $spfRecords = $dnsData->getSPFRecordsForDomain($domain);
            $spfRecord = $spfRecords[0] ?? '(none)';
        } catch (DNSLookupException $e) {
            $spfRecord = '(lookup exception)';
        }

        $this->assertTrue(
            in_array($result, $expectedResult),
            'Failed asserting that (expected) '.(
            (count($expectedResult) == 1)
                ? ($expectedResult[0].' equals ')
                : ('('.implode(', ', $expectedResult).') contains '))
            .'(result) '.$result.PHP_EOL
            .'IP address: '.$ipAddress.PHP_EOL
            .'SPF record: '.$spfRecord
        );
    }

    public function RFC4408DataProvider(): array
    {
        $scenarios = file_get_contents(__DIR__.DIRECTORY_SEPARATOR.'rfc4408-tests.yml');

        return $this->loadTestCases($scenarios);
    }

    protected function isScenarioAllowed(string $scenarioName): bool
    {
        return $scenarioName != 'Macro expansion rules';
    }

    protected function isTestAllowed(string $testName): bool
    {
        return true;
    }

}
