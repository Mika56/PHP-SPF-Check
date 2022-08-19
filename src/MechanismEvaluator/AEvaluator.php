<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\MechanismEvaluator;

use Mika56\SPFCheck\Mechanism\A;
use Mika56\SPFCheck\Mechanism\AbstractMechanism;
use Mika56\SPFCheck\Model\Result;
use Mika56\SPFCheck\SPFCheck;
use Symfony\Component\HttpFoundation\IpUtils;

class AEvaluator implements EvaluatorInterface
{

    public static function matches(AbstractMechanism $mechanism, string $target, Result $result, SPFCheck $spfCheck): bool
    {
        if(!$mechanism instanceof A) {
            throw new \LogicException();
        }
        $targetVersion = str_contains($target, ':') ? 6 : 4;

        $aRecords = $result->getDNSSession()->resolveA($mechanism->getHostname());
        if(empty($aRecords)) {
            $result->countVoidLookup();
        }

        $cidr = $targetVersion === 6 ? $mechanism->getCidr6() : $mechanism->getCidr4();
        foreach ($aRecords as $record) {
            $recordVersion = str_contains($record, ':') ? 6 : 4;
            if($recordVersion !== $targetVersion) {
                continue;
            }
            if(IpUtils::checkIp($target, $record.'/'.$cidr)) {
                return true;
            }
        }

        return false;
    }
}
