<?php
/**
 * Created by alex on 9/21/2016 11:36 AM
 */

namespace Mika56\SPFCheck;


class RealMxATest extends \PHPUnit_Framework_TestCase
{
    /** @var  SPFCheck */
    protected $SPFCheck;

    protected function setUp()
    {
        $this->SPFCheck = new SPFCheck(new DNSRecordGetter());
        parent::setUp();
    }

    public function testMX()
    {
        $this->assertEquals(SPFCheck::RESULT_PASS, $this->SPFCheck->isIPAllowed('148.163.156.1', 'ec.ibm.com'));
    }
	
	public function testA()
    {
        $this->assertEquals(SPFCheck::RESULT_PASS, $this->SPFCheck->isIPAllowed('199.212.215.11', 'justice.gc.ca'));
    }
}