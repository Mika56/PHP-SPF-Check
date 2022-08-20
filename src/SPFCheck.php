<?php

declare(strict_types=1);

namespace Mika56\SPFCheck;

use Mika56\SPFCheck\DNS\DNSRecordGetterInterface;
use Mika56\SPFCheck\DNS\Session;
use Mika56\SPFCheck\Exception\DNSLookupException;
use Mika56\SPFCheck\Exception\DNSLookupLimitReachedException;
use Mika56\SPFCheck\Exception\MacroSyntaxError;
use Mika56\SPFCheck\Exception\PermErrorException;
use Mika56\SPFCheck\Exception\TempErrorException;
use Mika56\SPFCheck\Mechanism\{A, AbstractMechanism, All, Exists, IncludeMechanism, IP, MX, PTR};
use Mika56\SPFCheck\MechanismEvaluator\{AEvaluator, AllEvaluator, ExistsEvaluator, IncludeEvaluator, IPEvaluator, MXEvaluator, PTREvaluator};
use Mika56\SPFCheck\Model\Query;
use Mika56\SPFCheck\Model\Record;
use Mika56\SPFCheck\Model\Result;
use Mika56\SPFCheck\Modifier\Explanation;
use Mika56\SPFCheck\Modifier\Redirect;
use const true;

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

    //public function getIPResult(string $ipAddress, string $domainName, ?Result $result = null): Result

    public function getResult(Query $query): Result
    {
        return $this->doGetResult($query);
    }

    private function doGetResult(Query $query, ?Result $result = null): Result
    {
        $domainName = $query->getDomainName();
        $ipAddress = $query->getIpAddress();
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

        $redirect = null;
        $result->setRecord($record);
        foreach ($record->getTerms() as $term) {
            if($term instanceof AbstractMechanism) {
                $evaluator = SPFCheck::getEvaluatorFor($term);
                try {
                    if ($evaluator === IncludeEvaluator::class) {
                        // Include evaluator needs access to SPFCheck::doGetResult
                        $matches = $evaluator::matches($term, $query, $result, function(Query $query, Result $result): Result {return $this->doGetResult($query, $result);});
                    }
                    else {
                        $matches = $evaluator::matches($term, $query, $result);
                    }
                }
                catch(DNSLookupLimitReachedException|PermErrorException|TempErrorException $e) {
                    $result->setResult($e instanceof TempErrorException ? Result::TEMPERROR : Result::PERMERROR, $e->getMessage());
                    $result->addStep($term, null);

                    return $result;
                }
                $result->addStep($term, $matches);
                if($matches) {
                    if($record->hasExplanation()) {
                        try {
                            $explanationHost = MacroUtils::expandMacro($record->getExplanation()->getHostname(), $query, $result->getDNSSession(), true);
                            $explanationHost = MacroUtils::truncateDomainName($explanationHost);
                            $explanationTXT = $result->getDNSSession()->resolveTXT($explanationHost);
                            if(count($explanationTXT) === 1) {
                                $explanation = MacroUtils::expandMacro($explanationTXT[0], $query, $result->getDNSSession(), true);
                                // Only allow ASCII explanations
                                if(1===preg_match('`^[[:ascii:]]*$`', $explanation)) {
                                    $result->setExplanation($explanation);
                                }
                            }
                        }
                        catch(DNSLookupException|MacroSyntaxError $e) {
                            /* If <domain-spec> is empty, or there are any DNS processing errors[...],
                            or if there are syntax errors in the explanation string then proceed as if no exp modifier was given. */
                        }
                    }
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
            try {
                $redirectTarget = MacroUtils::expandMacro($redirect->getHostname(), $query, $result->getDNSSession(), false);
                $redirectQuery = $query->createRedirectedQuery($redirectTarget);
                $redirectResult = $this->doGetResult($redirectQuery, $result);
                if($redirectResult->getResult() === Result::NONE) {
                    $redirectResult->setResult(Result::PERMERROR, Result::REDIRECT_RESULTED_IN_NONE);
                }

                return $redirectResult;
            }
            catch(MacroSyntaxError $e) {
                if($e->isFatal()) {
                    // However, c, r and t are only allowed in exp and should result in a PE if used in a redirect
                    $result->setResult(Result::PERMERROR);

                    return $result;
                }
            }
        }

        $result->setResult(Result::NEUTRAL);

        return $result;
    }

    /**
     * @param string $ipAddress The IP address to be tested
     * @param string $domain The domain to test the IP address against
     * @return string
     */
    public function getIPStringResult(string $ipAddress, string $domain): string
    {
        $query = new Query($ipAddress, $domain);
        $result = $this->getResult($query);

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
