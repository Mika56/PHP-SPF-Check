<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\Exception;

class MacroSyntaxError extends \Exception
{
    private bool $isFatal;

    public function __construct(bool $isFatal, $message = "", $code = 0, \Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
        $this->isFatal = $isFatal;
    }

    public function isFatal(): bool
    {
        return $this->isFatal;
    }

}
