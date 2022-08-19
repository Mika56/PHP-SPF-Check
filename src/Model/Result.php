<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\Model;

use Mika56\SPFCheck\DNS\Session;
use Mika56\SPFCheck\Exception\PermErrorException;

class Result
{
    public const PASS = 'Pass';
    public const SHORT_PASS = '+';
    public const FAIL = 'Fail';
    public const SHORT_FAIL = '-';
    public const SOFTFAIL = 'SoftFail';
    public const SHORT_SOFTFAIL = '~';
    public const NEUTRAL = 'Neutral';
    public const SHORT_NEUTRAL = '?';
    public const NONE = 'None';
    public const SHORT_NONE = 'NO';
    public const TEMPERROR = 'TempError';
    public const SHORT_TEMPERROR = 'TE';
    public const PERMERROR = 'PermError';
    public const SHORT_PERMERROR = 'PE';

    public const DEFAULT_RESULT = 'DefaultResult';
    public const A_DNS_LOOKUP_ERROR_OCCURED = 'DNSLookupError';
    public const DOMAIN_HAS_NO_SPF_RECORD = 'NoSPFRecord';
    public const DOMAIN_HAS_MORE_THAN_ONE_SPF_RECORD = 'MoreThanOneSPFRecord';
    public const DOMAIN_SPF_RECORD_INVALID = 'SPFRecordInvalid';
    public const REDIRECT_RESULTED_IN_NONE = 'RedirectResultedInNone';

    private Session $DNSSession;
    private string $result;
    private ?string $reason;
    private Record $record;
    private array $steps = [];
    private int $voidLookups = 0;

    public function __construct(Session $DNSSession)
    {
        $this->DNSSession = $DNSSession;
    }

    /**
     * @internal
     */
    public function setRecord(Record $record): self
    {
        $this->record = $record;

        return $this;
    }

    public function hasResult(): bool
    {
        return isset($this->result);
    }

    public function getResult(): string
    {
        return $this->result;
    }

    public function getShortResult(): string
    {
        switch($this->result) {
            case self::PASS:
                return '+';
            case self::FAIL:
                return '-';
            case self::SOFTFAIL:
                return '~';
            case self::NEUTRAL:
                return '?';
            case self::NONE:
                return 'NO';
            case self::TEMPERROR:
                return 'TE';
            case self::PERMERROR:
                return 'PE';
        }

        throw new \LogicException('Invalid result '.$this->result);
    }

    /**
     * @internal
     */
    public function setResult(string $result, ?string $reason = null): self
    {
        $this->result = $result;
        $this->reason = $reason;

        return $this;
    }

    /**
     * @internal
     */
    public function setShortResult(string $result): self
    {
        switch($result) {
            case '+':
                $this->result = self::PASS;
                break;
            case '-':
                $this->result = self::FAIL;
                break;
            case '~':
                $this->result = self::SOFTFAIL;
                break;
            case '?':
                $this->result = self::NEUTRAL;
                break;
            case 'NO':
                $this->result = self::NONE;
                break;
            case 'TE':
                $this->result = self::TEMPERROR;
                break;
            case 'PE':
                $this->result = self::PERMERROR;
                break;
            default:
                throw new \InvalidArgumentException('Invalid short result '.$result);
        }

        return $this;
    }

    /**
     * @internal
     */
    public function addStep(Term $term, ?bool $matches): self
    {
        $this->steps[] = [$term, $matches];

        return $this;
    }

    /**
     * @internal
     */
    public function getDNSSession(): Session
    {
        return $this->DNSSession;
    }

    /**
     * @throws PermErrorException
     * @internal
     */
    public function countVoidLookup(): void
    {
        if (++$this->voidLookups > 2) {
            throw new PermErrorException();
        }
    }

}
