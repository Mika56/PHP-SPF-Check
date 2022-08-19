<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\MechanismEvaluator;

use Mika56\SPFCheck\Exception\PermErrorException;
use Mika56\SPFCheck\Exception\TempErrorException;
use Mika56\SPFCheck\Mechanism\AbstractMechanism;
use Mika56\SPFCheck\Mechanism\IncludeMechanism;
use Mika56\SPFCheck\Model\Result;
use Mika56\SPFCheck\SPFCheck;

class IncludeEvaluator implements EvaluatorInterface
{

    public static function matches(AbstractMechanism $mechanism, string $target, Result $result, SPFCheck $spfCheck): bool
    {
        if(!$mechanism instanceof IncludeMechanism) {
            throw new \LogicException();
        }

        $result->getDNSSession()->countRedirect();

        $includeResult = $spfCheck->getIPResult($target, $mechanism->getHostname(), $result);
        switch($includeResult->getResult()) {
            case Result::PASS:
                return true;
            case Result::FAIL:
            case Result::SOFTFAIL:
            case Result::NEUTRAL:
                return false;
            case Result::TEMPERROR:
                throw new TempErrorException();
            case Result::PERMERROR:
            case Result::NONE:
            default:
                throw new PermErrorException();
        }

    }
}
