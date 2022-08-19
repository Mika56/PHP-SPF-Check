<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\MechanismEvaluator;

use Mika56\SPFCheck\Mechanism\AbstractMechanism;
use Mika56\SPFCheck\Model\Result;
use Mika56\SPFCheck\SPFCheck;

class AllEvaluator implements EvaluatorInterface
{

    public static function matches(AbstractMechanism $mechanism, string $target, Result $result, SPFCheck $spfCheck): bool
    {
        return true;
    }
}
