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
        foreach ($mxRecords as $ipAddresses) {
            $ipAddresses = array_filter($ipAddresses, function(string $address) use($targetVersion): bool {
                $addressVersion = str_contains($address, ':') ? 6 : 4;
                return $addressVersion === $targetVersion;
            });
            $ipAddresses = array_map(function(string $address) use($cidr): string {return $address.'/'.$cidr;}, $ipAddresses);

            if(IpUtils::checkIp($target, $ipAddresses)) {
                return true;
            }
        }

        return false;
    }
}
