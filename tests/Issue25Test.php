<?php
/**
 *
 * @author Mikael Peigney
 */

namespace Mika56\SPFCheck;

/**
 * This tests that A/AAAA, MX and PTR has separate request counts
 * @see https://github.com/Mika56/PHP-SPF-Check/pull/26#issuecomment-356751586
 * @see https://github.com/sdgathman/pyspf/blob/d9ee44addb98ede1ce3aec9fbf6cd84ff80da1fe/spf.py#L1288
 */
class Issue25Test extends \PHPUnit_Framework_TestCase
{
    public function testIssue7()
    {
        $SPFCheck = new SPFCheck(new DNSRecordGetterOpenSPF([
            'e1.example.com' => [
                ['SPF' => ['v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all']],
                ['A' => '1.2.3.8'],
                ['MX' => [10, 'e1.example.com']],
            ],
        ]));
        $this->assertEquals(SPFCheck::RESULT_FAIL, $SPFCheck->isIPAllowed('127.0.0.1', 'e1.example.com'));
    }

    public function testIssue7MXAtLimit()
    {
        $SPFCheck = new SPFCheck(new DNSRecordGetterOpenSPF([
            'e1.example.com' => [
                ['SPF' => ['v=spf1 mx mx mx mx mx mx mx mx mx mx ip4:1.2.3.4 -all']],
                ['A' => '1.2.3.8'],
                ['MX' => [10, 'e1.example.com']],
                ['MX' => [20, 'e1.example.com']],
                ['MX' => [30, 'e1.example.com']],
            ],
        ]));
        $this->assertEquals(SPFCheck::RESULT_PERMERROR, $SPFCheck->isIPAllowed('127.0.0.1', 'e1.example.com'));
    }

    public function testIssue7MXExceeded()
    {
        $SPFCheck = new SPFCheck(new DNSRecordGetterOpenSPF([
            'e1.example.com' => [
                ['SPF' => ['v=spf1 a mx a mx a mx a mx a ptr ip4:1.2.3.4 -all']],
                ['A' => '1.2.3.8'],
                ['MX' => [10, 'e1.example.com']],
                ['MX' => [20, 'e1.example.com']],
                ['MX' => [30, 'e1.example.com']],
            ],
        ]));
        $this->assertEquals(SPFCheck::RESULT_PERMERROR, $SPFCheck->isIPAllowed('127.0.0.1', 'e1.example.com'));
    }

    public function testIssue7PTR()
    {
        $SPFCheck = new SPFCheck(new DNSRecordGetterOpenSPF([
            'e1.example.com' => [
                ['SPF' => ['v=spf1 ptr ptr ptr ptr ptr ptr ptr ptr ptr ptr -all']],
                ['A' => '1.2.3.8'],
            ],
        ]));
        $this->assertEquals(SPFCheck::RESULT_FAIL, $SPFCheck->isIPAllowed('127.0.0.1', 'e1.example.com'));
    }

    public function testIssue7PTRAtLimit()
    {
        $SPFCheck = new SPFCheck(new DNSRecordGetterOpenSPF([
            'e1.example.com' => [
                ['SPF' => ['v=spf1 ptr ptr ptr ptr ptr ptr ptr ptr ptr ptr -all']],
                ['A' => '1.2.3.8'],
            ],
        ]));
        $this->assertEquals(SPFCheck::RESULT_FAIL, $SPFCheck->isIPAllowed('127.0.0.1', 'e1.example.com'));
    }

    public function testIssue7PTRExceeded()
    {
        $SPFCheck = new SPFCheck(new DNSRecordGetterOpenSPF([
            'e1.example.com' => [
                ['SPF' => ['v=spf1 ptr ptr ptr ptr ptr ptr ptr ptr ptr ptr ptr -all']],
                ['A' => '1.2.3.8'],
            ],
        ]));
        $this->assertEquals(SPFCheck::RESULT_PERMERROR, $SPFCheck->isIPAllowed('127.0.0.1', 'e1.example.com'));
    }
}