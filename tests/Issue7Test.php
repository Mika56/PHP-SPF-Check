<?php

declare(strict_types=1);

namespace Mika56\SPFCheck;


class Issue7Test extends \PHPUnit_Framework_TestCase
{
    protected SPFCheck $SPFCheck;

    protected function setUp()
    {
        $this->SPFCheck = new SPFCheck(new DNSRecordGetterIssue7());
        parent::setUp();
    }

    public function testIssue7()
    {
        $this->assertEquals(SPFCheck::RESULT_NONE, $this->SPFCheck->isIPAllowed('127.0.0.1', 'domain.com'));
    }
}
