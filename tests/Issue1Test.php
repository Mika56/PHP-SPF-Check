<?php

declare(strict_types=1);

namespace Mika56\SPFCheck;

class Issue1Test extends \PHPUnit_Framework_TestCase
{
    protected SPFCheck $SPFCheck;

    protected function setUp()
    {
        $this->SPFCheck = new SPFCheck(new DNSRecordGetterIssue1());
        parent::setUp();
    }

    public function testIssue1()
    {
        $this->assertEquals(SPFCheck::RESULT_PASS, $this->SPFCheck->isIPAllowed('127.0.0.1', 'domaina.com'));
    }
}
