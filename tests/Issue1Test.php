<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\Test;

use Mika56\SPFCheck\SPFCheck;
use PHPUnit\Framework\TestCase;

class Issue1Test extends TestCase
{
    protected SPFCheck $SPFCheck;

    protected function setUp(): void
    {
        $this->SPFCheck = new SPFCheck(new DNSRecordGetterIssue1());
        parent::setUp();
    }

    public function testIssue1()
    {
        $this->assertEquals(SPFCheck::RESULT_PASS, $this->SPFCheck->isIPAllowed('127.0.0.1', 'domaina.com'));
    }
}
