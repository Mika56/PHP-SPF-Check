<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\Mechanism;

abstract class NetworkMechanism extends HostnameMechanism
{

    protected int $cidr4;
    protected int $cidr6;

    public function __construct(string $rawTerm, string $qualifier, string $hostname, ?int $cidr4, ?int $cidr6)
    {
        parent::__construct($rawTerm, $qualifier, $hostname);
        $this->cidr4 = $cidr4 ?? 32;
        $this->cidr6 = $cidr6 ?? 128;
    }

    public function getCidr6(): int
    {
        return $this->cidr6;
    }

    public function getCidr4(): int
    {
        return $this->cidr4;
    }
}
