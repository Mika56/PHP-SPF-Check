<?php

declare(strict_types=1);

namespace Mika56\SPFCheck;


class Issue3Test extends \PHPUnit_Framework_TestCase
{
    protected SPFCheck $SPFCheck;

    protected function setUp()
    {
        $this->SPFCheck = new SPFCheck(new DNSRecordGetterIssue3());
        parent::setUp();
    }

    public function testIssue3()
    {
        $this->assertEquals(SPFCheck::RESULT_PERMERROR, $this->SPFCheck->isIPAllowed('127.0.0.1', 'domain.com'));
    }
}
