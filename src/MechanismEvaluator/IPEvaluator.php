<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\MechanismEvaluator;

use Mika56\SPFCheck\Mechanism\AbstractMechanism;
use Mika56\SPFCheck\Mechanism\IP;
use Mika56\SPFCheck\Model\Result;
use Mika56\SPFCheck\SPFCheck;
use Symfony\Component\HttpFoundation\IpUtils;

class IPEvaluator implements EvaluatorInterface
{

    public static function matches(AbstractMechanism $mechanism, string $target, Result $result, SPFCheck $spfCheck): bool
    {
        if(!$mechanism instanceof IP) {
            throw new \LogicException();
        }

        return IpUtils::checkIp($target, $mechanism->getNetwork().'/'.$mechanism->getCidr());
    }
}
