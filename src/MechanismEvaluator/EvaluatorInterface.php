<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\MechanismEvaluator;

use Mika56\SPFCheck\DNS\Session;
use Mika56\SPFCheck\Enum\Mechanism;
use Mika56\SPFCheck\Mechanism\AbstractMechanism;
use Mika56\SPFCheck\Model\Query;
use Mika56\SPFCheck\Model\Result;
use Mika56\SPFCheck\SPFCheck;
use Symfony\Component\HttpFoundation\IpUtils;

interface EvaluatorInterface
{

    public static function matches(AbstractMechanism $mechanism, Query $query, Result $result): bool;
}
