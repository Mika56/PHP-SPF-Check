<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\Test;


use Mika56\SPFCheck\Model\Result;
use Mika56\SPFCheck\SPFCheck;
use PHPUnit\Framework\TestCase;

class Issue7Test extends TestCase
{
    protected SPFCheck $SPFCheck;

    protected function setUp(): void
    {
        $this->SPFCheck = new SPFCheck(new DNSRecordGetterIssue7());
        parent::setUp();
    }

    public function testIssue7()
    {
        $this->assertEquals(Result::SHORT_NONE, $this->SPFCheck->getIPStringResult('127.0.0.1', 'domain.com'));
    }
}
