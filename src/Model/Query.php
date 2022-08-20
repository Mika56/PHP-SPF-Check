<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\Model;

class Query
{
    private string $ipAddress;
    private string $domainName;
    private ?string $helo;
    private ?string $sender;
    private ?string $originalDomainName = null;

    public function __construct(string $ipAddress, string $domainName, ?string $helo = null, ?string $sender = null)
    {
        if (preg_match('/^(:|0000:0000:0000:0000:0000):FFFF:/i', $ipAddress)) {
            $ipAddress = strrev(explode(':', strrev($ipAddress), 2)[0]);
        }

        $this->ipAddress = $ipAddress;
        $this->domainName = $domainName;
        $this->helo = $helo;
        $this->sender = $sender;
    }

    public function getIpAddress(): string
    {
        return $this->ipAddress;
    }

    public function getDomainName(): string
    {
        return $this->domainName;
    }

    public function getHelo(): ?string
    {
        return $this->helo;
    }

    public function getSender(): ?string
    {
        return $this->sender;
    }

    public function getOriginalDomainName(): ?string
    {
        return $this->originalDomainName;
    }

    public function createRedirectedQuery(string $redirectTarget): Query
    {
        $newQuery = new self($this->ipAddress, $redirectTarget, $this->helo, $this->sender);
        $newQuery->originalDomainName = $this->originalDomainName ?? $this->domainName;

        return $newQuery;
    }

}
