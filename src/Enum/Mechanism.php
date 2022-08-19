<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\Enum;

abstract class Mechanism
{
    public const ALL = 'all';
    public const IP4 = 'ip4';
    public const IP6 = 'ip6';
    public const A = 'a';
    public const MX = 'mx';
    public const PTR = 'ptr';
    public const EXISTS = 'exists';
    public const INCLUDE = 'include';
}
