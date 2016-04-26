<?php
/**
 *
 * @author Mikael Peigney
 */

namespace Mika56\SPFCheck;


use Mika56\SPFCheck\Exception\DNSLookupException;
use Symfony\Component\HttpFoundation\IpUtils;

class SPFCheck
{
    const RESULT_PASS = '+';
    const RESULT_FAIL = '-';
    const RESULT_SOFTFAIL = '~';
    const RESULT_NEUTRAL = '?';
    const RESULT_NONE = 'NO';
    const RESULT_PERMERROR = 'PE';
    const RESULT_TEMPERROR = 'TE';

    protected static function getValidResults()
    {
        return [self::RESULT_PASS, self::RESULT_FAIL, self::RESULT_SOFTFAIL, self::RESULT_NEUTRAL];
    }

    const MECHANISM_ALL = 'all';
    const MECHANISM_IP4 = 'ip4';
    const MECHANISM_IP6 = 'ip6';
    const MECHANISM_A = 'a';
    const MECHANISM_MX = 'mx';
    const MECHANISM_PTR = 'ptr';
    const MECHANISM_EXISTS = 'exists';
    const MECHANISM_INCLUDE = 'include';
    const MODIFIER_REDIRECT = 'redirect';

    /** @var  DNSRecordGetterInterface */
    protected $DNSRecordGetter;

    /**
     * SPFCheck constructor.
     * @param DNSRecordGetterInterface $DNSRecordGetter
     */
    public function __construct(DNSRecordGetterInterface $DNSRecordGetter)
    {
        $this->DNSRecordGetter = $DNSRecordGetter;
    }

    /**
     * @param string $ipAddress The IP address to be tested
     * @param string $domain The domain to test the IP address against
     * @return string
     */
    public function isIPAllowed($ipAddress, $domain)
    {
        try {
            $spfRecord = $this->DNSRecordGetter->getSPFRecordForDomain($domain);
        } catch (DNSLookupException $e) {
            return self::RESULT_TEMPERROR;
        }

        if (!$spfRecord) {
            return self::RESULT_NONE;
        }

        $recordParts = explode(' ', $spfRecord);
        array_shift($recordParts); // Remove first part (v=spf1)
        foreach ($recordParts as $recordPart) {
            if (false !== ($result = $this->ipMatchesPart($ipAddress, $recordPart, $domain))) {
                return $result;
            }
        }

        return self::RESULT_NEUTRAL;
    }

    protected function ipMatchesPart($ipAddress, $part, $matchingDomain)
    {
        $qualifier = substr($part, 0, 1);
        if (!in_array($qualifier, self::getValidResults())) {
            $qualifier = self::RESULT_PASS;
            $condition = $part;
        } else {
            $condition = substr($part, 1);
        }

        $operandOption = $operand = null;
        if (1 == preg_match('`:|=`', $condition)) {
            list($mechanism, $operand) = preg_split('`:|=`', $condition, 2);
        } elseif (false !== stripos($condition, '/')) {
            list($mechanism, $operandOption) = explode('/', $condition, 2);
        } else {
            $mechanism = $condition;
        }

        switch ($mechanism) {
            case self::MECHANISM_ALL:
                return $qualifier;
                break;

            /** @noinspection PhpMissingBreakStatementInspection */
            case self::MECHANISM_IP4:
                if (false === stripos($operand, '/')) {
                    $operand .= '/32';
                }
            case self::MECHANISM_IP6:
                if (false === stripos($operand, '/')) {
                    $operand .= '/128';
                }
                if (IpUtils::checkIp($ipAddress, $operand)) {
                    return $qualifier;
                }
                break;

            case self::MECHANISM_A:
                $domain = $operand ? $operand : $matchingDomain;
                if (false !== stripos($domain, '/')) {
                    list($domain, $cidr) = explode('/', $domain);
                }
                if (!is_null($operandOption)) {
                    $cidr = $operandOption;
                }
                $validIpAddresses = $this->DNSRecordGetter->resolveA($domain);
                if (isset($cidr)) {
                    foreach ($validIpAddresses as &$validIpAddress) {
                        $validIpAddress .= '/'.$cidr;
                    }
                }

                if (IpUtils::checkIp($ipAddress, $validIpAddresses)) {
                    return $qualifier;
                }
                break;

            case self::MECHANISM_MX:
                $domain = $operand ? $operand : $matchingDomain;
                if (false !== stripos($domain, '/')) {
                    list($domain, $cidr) = explode('/', $domain);
                }
                if (!is_null($operandOption)) {
                    $cidr = $operandOption;
                }

                $validIpAddresses = [];
                $mxServers        = $this->DNSRecordGetter->resolveMx($domain);
                foreach ($mxServers as $mxServer) {
                    if (false !== filter_var($mxServer, FILTER_VALIDATE_IP)) {
                        $validIpAddresses[] = $mxServer;
                    } else {
                        foreach ($this->DNSRecordGetter->resolveA($mxServer) as $mxIpAddress) {
                            $validIpAddresses[] = $mxIpAddress;
                        }
                    }
                }
                if (isset($cidr)) {
                    foreach ($validIpAddresses as &$validIpAddress) {
                        $validIpAddress .= '/'.$cidr;
                    }
                }

                if (IpUtils::checkIp($ipAddress, $validIpAddresses)) {
                    return $qualifier;
                }
                break;

            case self::MECHANISM_PTR:
                $domain = $operand ? $operand : $matchingDomain;

                $ptrRecords       = $this->DNSRecordGetter->resolvePtr($ipAddress);
                $validIpAddresses = [];

                if ($ptrRecords) {
                    foreach ($ptrRecords as $ptrRecord) {
                        $aRecords = $this->DNSRecordGetter->resolveA($ptrRecord);
                        if ($aRecords) {
                            foreach ($aRecords as $domainIpAddress) {
                                $validIpAddresses[] = $domainIpAddress;
                            }
                        }
                    }
                }

                // "at least one of the A records for a PTR hostname must match the original client IP"
                if (IpUtils::checkIp($ipAddress, $validIpAddresses)) {
                    return $qualifier;
                }

                // "If a valid hostname ends in domain, this mechanism matches"
                if ($ptrRecords) {
                    foreach ($ptrRecords as $ptrRecord) {
                        if (substr($ptrRecord, -strlen($domain)) == $domain) {
                            return $qualifier;
                        }
                    }
                }

                break;

            case self::MECHANISM_EXISTS:
                if ($this->DNSRecordGetter->exists($operand)) {
                    return $qualifier;
                }
                break;

            case self::MECHANISM_INCLUDE:
                $includeResult = $this->isIPAllowed($ipAddress, $operand);
                if ($includeResult == self::RESULT_PASS) {
                    return $includeResult;
                }
                break;
            case self::MODIFIER_REDIRECT:
                return $this->isIPAllowed($ipAddress, $operand);
                break;
            default:

                return self::RESULT_PERMERROR;
                break;
        }

        return false;
    }
}