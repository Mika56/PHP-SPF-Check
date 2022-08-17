<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\Test;


use PHPUnit\Framework\TestCase;
use Symfony\Component\Yaml\Yaml;

abstract class OpenSPFTest extends TestCase
{
    protected abstract function isScenarioAllowed(string $scenarioName): bool;

    protected abstract function isTestAllowed(string $testName): bool;

    protected abstract function fixZoneData(string $scenarioName, array $zoneData): array;

    protected function loadTestCases(string $scenarios): array
    {
        $testCases = [];
        $scenarios = explode('---', $scenarios);
        foreach ($scenarios as $scenario) {
            $scenario = Yaml::parse($scenario);
            if ($scenario && $this->isScenarioAllowed($scenario['description'])) {
                $scenario['zonedata'] = $this->fixZoneData($scenario['description'], $scenario['zonedata']);
                $dnsData              = new DNSRecordGetterOpenSPF($scenario['zonedata']);
                foreach ($scenario['tests'] as $testName => $test) {
                    if ($this->isTestAllowed($testName)) {
                        $atPosition = strrchr($test['mailfrom'], '@');
                        if($atPosition === false) {
                            $domain = $test['helo'];
                        }
                        else {
                            $domain = substr($atPosition, 1);
                        }
                        $testCases[$scenario['description'].': '.$testName] = [
                            $test['host'], // $ipAddress
                            $domain,
                            $dnsData,
                            self::strToConst($test['result']), // $expectedResult
                        ];
                    }
                }
            }
        }

        return $testCases;
    }

    protected static function strToConst($result)
    {
        if (!is_array($result)) {
            $result = array($result);
        }

        foreach ($result as &$res) {
            $constantName = '\Mika56\SPFCheck\SPFCheck::RESULT_'.strtoupper($res);
            if (defined($constantName)) {
                $res = constant($constantName);
            } else {
                throw new \InvalidArgumentException('Result '.$res.' is an invalid result');
            }
        }

        return $result;
    }
}
