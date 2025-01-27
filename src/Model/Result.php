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

    public const DEFAULT_RESULT = 'DEFAULT'; // This is the default string used in rfc4408/7208-tests.yml
    public const A_DNS_LOOKUP_ERROR_OCCURED = 'DNSLookupError';
    public const DOMAIN_HAS_NO_SPF_RECORD = 'NoSPFRecord';
    public const DOMAIN_HAS_MORE_THAN_ONE_SPF_RECORD = 'MoreThanOneSPFRecord';
    public const DOMAIN_SPF_RECORD_INVALID = 'SPFRecordInvalid';
    public const REDIRECT_RESULTED_IN_NONE = 'RedirectResultedInNone';
    public const TOO_MANY_DNS_LOOKUPS = 'TooManyDNSLookups';

    private Session $DNSSession;
    private string $result;
    private ?string $explanation = self::DEFAULT_RESULT; // If no "exp" modifier is present, then either a default explanation string or an empty explanation string may be returned.
    private ?Record $record = null;
    protected int $requestCount = 0;
    protected int $requestMXCount = 0;
    protected int $requestPTRCount = 0;
    /**
     * @var array{array{0: Term, 1: ?bool}}
     */
    private array $steps = [];
    private int $voidLookups = 0;

    public function __construct(Session $DNSSession)
    {
        $this->DNSSession = $DNSSession;
    }

    public function getRecord(): ?Record
    {
        return $this->record;
    }

    /**
     * @return array{array{0: Term, 1: ?bool}}
     */
    public function getSteps(): array
    {
        return $this->steps;
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
                return self::SHORT_PASS;
            case self::FAIL:
                return self::SHORT_FAIL;
            case self::SOFTFAIL:
                return self::SHORT_SOFTFAIL;
            case self::NEUTRAL:
                return self::SHORT_NEUTRAL;
            case self::NONE:
                return self::SHORT_NONE;
            case self::TEMPERROR:
                return self::SHORT_TEMPERROR;
            case self::PERMERROR:
                return self::SHORT_PERMERROR;
        }

        throw new \LogicException('Invalid result '.$this->result);
    }

    public function getExplanation(): ?string
    {
        return $this->explanation;
    }

    public function getRequestCount(): int
    {
        return $this->requestCount;
    }

    public function getRequestMXCount(): int
    {
        return $this->requestMXCount;
    }

    public function getRequestPTRCount(): int
    {
        return $this->requestPTRCount;
    }

    public function getVoidLookups(): int
    {
        return $this->voidLookups;
    }

    /**
     * @internal
     */
    public function setRecord(Record $record): self
    {
        $this->record = $record;

        return $this;
    }

    /**
     * @internal
     */
    public function setResult(string $result, ?string $explanation = null): self
    {
        $this->result      = $result;
        if($explanation) {
            $this->explanation = $explanation;
        }
        $this->setDNSLookups();

        return $this;
    }

    /**
     * @internal
     */
    public function setShortResult(string $result, ?string $explanation = null): self
    {
        switch($result) {
            case '+':
                $result = self::PASS;
                break;
            case '-':
                $result = self::FAIL;
                break;
            case '~':
                $result = self::SOFTFAIL;
                break;
            case '?':
                $result = self::NEUTRAL;
                break;
            case 'NO':
                $result = self::NONE;
                break;
            case 'TE':
                $result = self::TEMPERROR;
                break;
            case 'PE':
                $result = self::PERMERROR;
                break;
            default:
                throw new \InvalidArgumentException('Invalid short result '.$result);
        }

        return $this->setResult($result, $explanation);
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

    private function setDNSLookups()
    {
        $this->requestCount = $this->DNSSession->getRequestCount();
        $this->requestMXCount = $this->DNSSession->getRequestMXCount();
        $this->requestPTRCount = $this->DNSSession->getRequestPTRCount();
    }

}
