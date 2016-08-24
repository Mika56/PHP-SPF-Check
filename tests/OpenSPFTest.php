<?php
/**
 *
 * @author Mikael Peigney
 */

namespace Mika56\SPFCheck;


use Symfony\Component\Yaml\Yaml;

abstract class OpenSPFTest extends \PHPUnit_Framework_TestCase
{
    abstract function isScenarioAllowed($scenarioName);

    abstract function isTestAllowed($testName);

    abstract function fixZoneData($scenarioName, $zoneData);

    public function loadTestCases($scenarios)
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
                        $domain = substr(strrchr($test['mailfrom'], '@'), 1);
                        if (empty($domain)) {
                            $domain = $test['helo'];
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