<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\MechanismEvaluator;

use Mika56\SPFCheck\Mechanism\AbstractMechanism;
use Mika56\SPFCheck\Mechanism\PTR;
use Mika56\SPFCheck\Model\Query;
use Mika56\SPFCheck\Model\Result;

class PTREvaluator implements EvaluatorInterface
{

    public static function matches(AbstractMechanism $mechanism, Query $query, Result $result): bool
    {
        if(!$mechanism instanceof PTR) {
            throw new \LogicException();
        }

        $ptrRecords = $result->getDNSSession()->resolvePTR($query->getIpAddress());
        foreach ($ptrRecords as $ptrRecord) {
            if(str_ends_with($ptrRecord, $mechanism->getHostname())) {
                return true;
            }
        }

        return false;
    }
}
