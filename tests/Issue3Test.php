<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\Test;


use Mika56\SPFCheck\SPFCheck;
use PHPUnit\Framework\TestCase;

class Issue3Test extends TestCase
{
    protected SPFCheck $SPFCheck;

    protected function setUp(): void
    {
        $this->SPFCheck = new SPFCheck(new DNSRecordGetterIssue3());
        parent::setUp();
    }

    public function testIssue3()
    {
        $this->assertEquals(SPFCheck::RESULT_PERMERROR, $this->SPFCheck->isIPAllowed('127.0.0.1', 'domain.com'));
    }
}
