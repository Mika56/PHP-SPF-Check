<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\Mechanism;

class IP extends AbstractMechanism
{
    public const VERSION_4 = '4';
    public const VERSION_6 = '6';

    private string $version;
    private string $network;
    private int $cidr;

    public function __construct(string $rawTerm, string $qualifier, string $version, string $network, ?int $cidr)
    {
        parent::__construct($rawTerm, $qualifier);
        $this->version = $version;
        $this->network = $network;
        if($cidr === null) {
            switch($this->version) {
                case self::VERSION_4:
                    $cidr = 32;
                    break;
                case self::VERSION_6:
                    $cidr = 128;
                    break;
            }
        }
        $this->cidr = $cidr;
    }

    public function getNetwork(): string
    {
        return $this->network;
    }

    public function getCidr(): int
    {
        return $this->cidr;
    }

}
