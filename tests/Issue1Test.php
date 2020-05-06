<?php
/**
 * Created by mikaelp on 4/26/2016 9:36 AM
 */

namespace Mika56\SPFCheck;


class Issue1Test extends \PHPUnit_Framework_TestCase
{
    /** @var  SPFCheck */
    protected $SPFCheck;

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