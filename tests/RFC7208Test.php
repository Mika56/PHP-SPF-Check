<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\Test;

use Mika56\SPFCheck\DNS\DNSRecordGetterInterface;
use Mika56\SPFCheck\Exception\DNSLookupException;
use Mika56\SPFCheck\Model\Query;
use Mika56\SPFCheck\SPFCheck;

class RFC7208Test extends OpenSPFTest
{
    /**
     * @dataProvider RFC7208DataProvider
     */
    public function testRFC7208(string $ipAddress, string $domain, DNSRecordGetterInterface $dnsData, array $expectedResult, ?string $explanation, ?string $helo = null, ?string $sender = null)
    {
        $spfCheck = new SPFCheck($dnsData);
        $result   = $spfCheck->getResult(new Query($ipAddress, $domain, $helo, $sender));

        try {
            $spfRecords = $dnsData->getSPFRecordsForDomain($domain);
            $spfRecord = $spfRecords[0] ?? '(none)';
        } catch (DNSLookupException $e) {
            $spfRecord = '(lookup exception)';
        }

        $this->assertTrue(
            in_array($result->getShortResult(), $expectedResult),
            'Failed asserting that (expected) '.(
            (count($expectedResult) == 1)
                ? ($expectedResult[0].' equals ')
                : ('('.implode(', ', $expectedResult).') contains '))
            .'(result) '.$result->getShortResult().PHP_EOL
            .'IP address: '.$ipAddress.PHP_EOL
            .'SPF record: '.$spfRecord
        );
        if($explanation) {
            $this->assertEquals($explanation, $result->getExplanation(), 'Incorrect explanation');
        }
    }

    public function RFC7208DataProvider(): array
    {
        $scenarios = file_get_contents(__DIR__.DIRECTORY_SEPARATOR.'rfc7208-tests.yml');
        // Apparently there is a YML error in that file
        $scenarios = str_replace('Result is none if checking SPF records only', '>-'."\n".'      Result is none if checking SPF records only', $scenarios);

        return $this->loadTestCases($scenarios);
    }

    protected function isTestAllowed(string $testName): bool
    {
        $ignoredTests = [
            'spftimeout', // This test fails because DNSRecordGetterOpenSPF returns SPF records. However, DnsRecordGetter does not, so we just ignore those tests
            'exp-only-macro-char', // Tests that %{r} is not used in a disallowed context. However, it actually tries it in an allowed context, so this test always fails
        ];

        return !in_array($testName, $ignoredTests);
    }

}
