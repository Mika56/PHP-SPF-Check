<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\MechanismEvaluator;

use Mika56\SPFCheck\Mechanism\AbstractMechanism;
use Mika56\SPFCheck\Mechanism\MX;
use Mika56\SPFCheck\Model\Result;
use Mika56\SPFCheck\SPFCheck;
use Symfony\Component\HttpFoundation\IpUtils;

class MXEvaluator implements EvaluatorInterface
{

    public static function matches(AbstractMechanism $mechanism, string $target, Result $result, SPFCheck $spfCheck): bool
    {
        if(!$mechanism instanceof MX) {
            throw new \LogicException();
        }
        $targetVersion = str_contains($target, ':') ? 6 : 4;
        $cidr = $targetVersion === 6 ? $mechanism->getCidr6() : $mechanism->getCidr4();

        $mxRecords = $result->getDNSSession()->resolveMX($mechanism->getHostname());
        foreach ($mxRecords as $mxRecord) {
            if(IpUtils::checkIp($target, array_map(function(string $record) use($cidr): string {return $record.'/'.$cidr;}, $mxRecord))) {
                return true;
            }
        }

        return false;
    }
}
