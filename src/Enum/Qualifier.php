<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\Enum;

abstract class Qualifier
{
    public const PASS = '+';
    public const FAIL = '-';
    public const NEUTRAL = '?';
    public const SOFTFAIL = '~';
}
