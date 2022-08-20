<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\MechanismEvaluator;

use Mika56\SPFCheck\Exception\DNSLookupException;
use Mika56\SPFCheck\Exception\TempErrorException;
use Mika56\SPFCheck\MacroUtils;
use Mika56\SPFCheck\Mechanism\AbstractMechanism;
use Mika56\SPFCheck\Mechanism\Exists;
use Mika56\SPFCheck\Model\Query;
use Mika56\SPFCheck\Model\Result;

class ExistsEvaluator implements EvaluatorInterface
{

    public static function matches(AbstractMechanism $mechanism, Query $query, Result $result): bool
    {
        if(!$mechanism instanceof Exists) {
            throw new \LogicException();
        }

        $hostname = $mechanism->getHostname();
        $hostname = MacroUtils::expandMacro($hostname, $query, $result->getDNSSession(), false);
        $hostname = MacroUtils::truncateDomainName($hostname);
        // 5.7/3: "The lookup type is A even when the connection type is IPv6"
        try {
            $records = $result->getDNSSession()->resolveA($hostname, true);
        }
        catch (DNSLookupException $e) {
            throw new TempErrorException('', 0, $e);
        }
        foreach($records as $record) {
            return true;
        }

        return false;
    }
}
