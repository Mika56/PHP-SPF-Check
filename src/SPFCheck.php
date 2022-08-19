<?php

declare(strict_types=1);

namespace Mika56\SPFCheck;

use Mika56\SPFCheck\DNS\DNSRecordGetterInterface;
use Mika56\SPFCheck\DNS\Session;
use Mika56\SPFCheck\Exception\DNSLookupException;
use Mika56\SPFCheck\Exception\DNSLookupLimitReachedException;
use Mika56\SPFCheck\Exception\PermErrorException;
use Mika56\SPFCheck\Exception\TempErrorException;
use Mika56\SPFCheck\Mechanism\{A, AbstractMechanism, All, Exists, IncludeMechanism, IP, MX, PTR};
use Mika56\SPFCheck\MechanismEvaluator\{AEvaluator, AllEvaluator, ExistsEvaluator, IncludeEvaluator, IPEvaluator, MXEvaluator, PTREvaluator};
use Mika56\SPFCheck\Model\Record;
use Mika56\SPFCheck\Model\Result;
use Mika56\SPFCheck\Modifier\Redirect;

class SPFCheck
{

    protected DNSRecordGetterInterface $DNSRecordGetter;

    public function __construct(DNSRecordGetterInterface $DNSRecordGetter)
    {
        $this->DNSRecordGetter = $DNSRecordGetter;
    }

    /**
     * @param string $domainName
     * @return Record[]
     * @throws DNSLookupException
     */
    public function getDomainSPFRecords(string $domainName): array
    {
        $result = [];

        $records = $this->DNSRecordGetter->getSPFRecordsForDomain($domainName);
        foreach ($records as $record) {
            $result[] = new Record($domainName, $record);
        }

        return $result;
    }

    public function getIPResult(string $ipAddress, string $domainName, ?Result $result = null): Result
    {
        $result??= new Result(new Session($this->DNSRecordGetter));

        if(empty($domainName)) {
            $result->setResult(Result::NONE);

            return $result;
        }

        try {
            $records = $this->getDomainSPFRecords($domainName);
        } catch (DNSLookupException $e) {
            $result->setResult(Result::TEMPERROR, Result::A_DNS_LOOKUP_ERROR_OCCURED);

            return $result;
        }

        if (count($records) == 0) {
            $result->setResult(Result::NONE, Result::DOMAIN_HAS_NO_SPF_RECORD);

            return $result;
        }
        if (count($records) > 1) {
            $result->setResult(Result::PERMERROR, Result::DOMAIN_HAS_MORE_THAN_ONE_SPF_RECORD);

            return $result;
        }

        $record = $records[0];
        if (!$record->isValid()) {
            $result->setResult(Result::PERMERROR, Result::DOMAIN_SPF_RECORD_INVALID);

            return $result;
        }

        if (preg_match('/^(:|0000:0000:0000:0000:0000):FFFF:/i', $ipAddress)) {
            $ipAddress = strrev(explode(':', strrev($ipAddress), 2)[0]);
        }

        $redirect = null;
        $result->setRecord($record);
        foreach ($record->getTerms() as $term) {
            if($term instanceof AbstractMechanism) {
                $evaluator = SPFCheck::getEvaluatorFor($term);
                try {
                    $matches = $evaluator::matches($term, $ipAddress, $result, $this);
                }
                catch(DNSLookupLimitReachedException|PermErrorException|TempErrorException $e) {
                    $result->setResult($e instanceof TempErrorException ? Result::TEMPERROR : Result::PERMERROR);
                    $result->addStep($term, null);

                    return $result;
                }
                $result->addStep($term, $matches);
                if($matches) {
                    $result->setShortResult($term->getQualifier());

                    return $result;
                }
            }
            elseif($term instanceof Redirect) {
                $redirect = $term;
            }
        }
        if(!$result->hasResult() && $redirect) {
            try {
                $result->getDNSSession()->countRedirect();
            } catch (DNSLookupLimitReachedException $e) {
                $result->setResult(Result::PERMERROR);
                $result->addStep($redirect, null);

                return $result;
            }
            $redirectResult = $this->getIPResult($ipAddress, $redirect->getHostname(), $result);
            if($redirectResult->getResult() === Result::NONE) {
                $redirectResult->setResult(Result::PERMERROR, Result::REDIRECT_RESULTED_IN_NONE);
            }

            return $redirectResult;
        }

        $result->setResult(Result::NEUTRAL, Result::DEFAULT_RESULT);

        return $result;
    }

    /**
     * @param string $ipAddress The IP address to be tested
     * @param string $domain The domain to test the IP address against
     * @return string
     */
    public function getIPStringResult(string $ipAddress, string $domain): string
    {
        $result = $this->getIPResult($ipAddress, $domain);

        return $result->getShortResult();
    }

    private static function getEvaluatorFor(AbstractMechanism $term): string
    {
        switch(true) {
            case $term instanceof IP:
                return IPEvaluator::class;
            case $term instanceof All:
                return AllEvaluator::class;
            case $term instanceof A:
                return AEvaluator::class;
            case $term instanceof MX:
                return MXEvaluator::class;
            case $term instanceof PTR:
                return PTREvaluator::class;
            case $term instanceof Exists:
                return ExistsEvaluator::class;
            case $term instanceof IncludeMechanism:
                return IncludeEvaluator::class;
        }
    }
}
