<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\Test;


use Mika56\SPFCheck\DNS\DNSRecordGetterInterface;
use Mika56\SPFCheck\Exception\DNSLookupException;
use Mika56\SPFCheck\Model\Query;
use Mika56\SPFCheck\SPFCheck;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Yaml\Yaml;

final class SPFTest extends TestCase
{

    /**
     * @dataProvider loadTestCases
     */
    public function testCases($ipAddress, $domain, DNSRecordGetterInterface $dnsData, $expectedResult, ?string $explanation, ?string $helo = null, ?string $sender = null)
    {
        $spfCheck = new SPFCheck($dnsData);
        $result = $spfCheck->getResult(new Query($ipAddress, $domain, $helo, $sender));

        try {
            $spfRecords = $spfCheck->getDomainSPFRecords($domain);
            $spfRecord = !empty($spfRecords) ? $spfRecords[0]->getRawRecord() : '(none)';
        } catch (DNSLookupException $e) {
            $spfRecord = '(lookup exception)';
        }

        $this->assertTrue(
            in_array($result->getShortResult(), $expectedResult),
            'Failed asserting that (expected) '.(
            (count($expectedResult) == 1)
                ? ($expectedResult[0].' equals ')
                : ('('.implode(', ', $expectedResult).') contains '))
            .'(result) '.$result->getShortResult().' - '.$result->getExplanation().PHP_EOL
            .'IP address: '.$ipAddress.PHP_EOL
            .'SPF record: '.$spfRecord
        );
        if($explanation) {
            $this->assertEquals($explanation, $result->getExplanation(), 'Incorrect explanation');
        }
    }

    public function loadTestCases(): array
    {
        $tests = glob(__DIR__.DIRECTORY_SEPARATOR.'*', GLOB_ONLYDIR);
        $testCases = [];
        foreach ($tests as $test) {
            $this->loadTests(basename($test), $testCases);
        }

        return $testCases;
    }

    private function loadTests(string $testFolder, array &$testCases): void
    {
        $basename = __DIR__.DIRECTORY_SEPARATOR.$testFolder.DIRECTORY_SEPARATOR.$testFolder;
        $testFile = $basename.'-tests.yml';
        if(!is_file($testFile)) {
            throw new \Exception('Unable to load test '.$testFolder);
        }

        $tests = file_get_contents($testFile);
        if(is_file($basename.'-datafix.yml')) {
            $fixes = Yaml::parseFile($basename.'-datafix.yml');
            foreach ($fixes as $fix) {
                ['search' => $search, 'replace' => $replace] = $fix;
                $tests = str_replace($search, $replace, $tests);
            }
        }
        $excludedTests = is_file($basename.'-ignore.yml') ? Yaml::parseFile($basename.'-ignore.yml') : [];

        $scenarios = explode('---', $tests);
        foreach ($scenarios as $scenario) {
            $scenario = Yaml::parse($scenario);
            if(!$scenario) {
                continue;
            }
            $dnsData = new DNSRecordGetterOpenSPF($scenario['zonedata']);
            foreach ($scenario['tests'] as $testName => $test) {
                if (in_array($testName, $excludedTests)) {
                    continue;
                }
                $atPosition = strrchr($test['mailfrom'], '@');
                if($atPosition === false) {
                    $domain = $test['helo'];
                }
                else {
                    $domain = substr($atPosition, 1);
                }
                $testCases['['.$testFolder.'] '.$scenario['description'].': '.$testName] = [
                    $test['host'], // $ipAddress
                    $domain,
                    $dnsData,
                    self::strToConst($test['result']), // $expectedResult
                        $test['explanation'] ?? null,
                        $test['helo'] ?? null,
                        $test['mailfrom'] ?? null,
                ];
            }
        }
    }

    protected static function strToConst($result)
    {
        if (!is_array($result)) {
            $result = array($result);
        }

        foreach ($result as &$res) {
            $constantName = '\Mika56\SPFCheck\Model\Result::SHORT_'.strtoupper($res);
            if (defined($constantName)) {
                $res = constant($constantName);
            } else {
                throw new \InvalidArgumentException('Result '.$res.' is an invalid result');
            }
        }

        return $result;
    }
}
