<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\Modifier;

class Explanation extends AbstractModifier
{

    private string $hostname;

    public function __construct(string $rawTerm, string $hostname)
    {
        $this->hostname = $hostname;
        parent::__construct($rawTerm);
    }

    public function getHostname(): string
    {
        return $this->hostname;
    }
}
