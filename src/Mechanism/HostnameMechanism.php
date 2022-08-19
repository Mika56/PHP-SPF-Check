<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\Mechanism;

abstract class HostnameMechanism extends AbstractMechanism
{

    protected string $hostname;

    public function __construct(string $rawTerm, string $qualifier, string $hostname)
    {
        parent::__construct($rawTerm, $qualifier);
        $this->hostname = $hostname;
    }

    public function getHostname(): string
    {
        return $this->hostname;
    }
}
