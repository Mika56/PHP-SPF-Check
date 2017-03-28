<?php
/**
 *
 * @author Mikael Peigney
 */

namespace Mika56\SPFCheck;


use Mika56\SPFCheck\Exception\DNSLookupException;
use Mika56\SPFCheck\Exception\DNSLookupLimitReachedException;
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
    const RESULT_DEFINITIVE_PERMERROR = 'DPE'; // Special result for recursion limit, that cannot be ignored and is transformed to PERMERROR

    /**
     * Stores any "redirect" modifier value for later redirection
     * @var string|null
     */
    private $redirect;
    private $voidLookup = 0;

    protected static function getValidResults()
    {
        return array(self::RESULT_PASS, self::RESULT_FAIL, self::RESULT_SOFTFAIL, self::RESULT_NEUTRAL);
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
    const MODIFIER_EXP = 'exp';

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
        return $this->doIsIPAllowed($ipAddress, $domain, true);
    }

    protected function doIsIPAllowed($ipAddress, $domain, $resetRequestCount)
    {
        if (!$domain) {
            return self::RESULT_NONE;
        }

        $this->redirect = null;
        if ($resetRequestCount) {
            $this->voidLookup = 0;
            $this->DNSRecordGetter->resetRequestCount();
        }

        // Handle IPv4 address in IPv6 format
        if (preg_match('/^(:|0000:0000:0000:0000:0000):FFFF:/i', $ipAddress)) {
	        $explode = explode(':', strrev($ipAddress), '2');
	        $ipAddress = strrev($explode[0]);
        }

        $result = $this->doCheck($ipAddress, $domain);
        if ($result == self::RESULT_DEFINITIVE_PERMERROR) {
            $result = self::RESULT_PERMERROR;
        }

        return $result;
    }

    private function doCheck($ipAddress, $domain)
    {
        try {
            $spfRecords = $this->DNSRecordGetter->getSPFRecordForDomain($domain);
        } catch (DNSLookupException $e) {
            return self::RESULT_TEMPERROR;
        }

        if (count($spfRecords) == 0) {
            return self::RESULT_NONE;
        }
        if (count($spfRecords) > 1) {
            return self::RESULT_PERMERROR;
        }
        $spfRecord = $spfRecords[0];
        if (!self::isSPFValid($spfRecord)) {
            return self::RESULT_PERMERROR;
        }

        $recordParts = explode(' ', $spfRecord);
        array_shift($recordParts); // Remove first part (v=spf1)
        if (count($recordParts) == 0) {
            $recordParts = array('?all');
        }
        $result = false;

        foreach ($recordParts as $recordPart) {
            try {
                if (false !== ($result = $this->ipMatchesPart($ipAddress, $recordPart, $domain))) {
                    return $result;
                }
            } catch (DNSLookupLimitReachedException $e) {
                return self::RESULT_DEFINITIVE_PERMERROR;
            }
        }

        if ($result === false && $this->redirect) {
            $result = $this->doIsIPAllowed($ipAddress, $this->redirect, false);
            // In a redirect, if no SPF is found or if domain does not exist, it should return PermError (RFC4408 6.1/4)
            if ($result == self::RESULT_NONE) {
                $result = self::RESULT_PERMERROR;
            }

            return $result;
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

                // CIDR 0 matches any IP Address
                list(, $cidr) = explode('/', $operand, 2);
                if (isset($cidr) && $cidr == 0) {
                    return $qualifier;
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
                if (isset($cidr) && !is_numeric($cidr)) {
                    // If cidr is not numeric, then it's not a cidr
                    // RFC 4408 allow any character, including /, in a domain name
                    $domain .= '/'.$cidr;
                    unset($cidr);
                }
                $this->DNSRecordGetter->countRequest();
                $validIpAddresses = $this->DNSRecordGetter->resolveA($domain);
                if (count($validIpAddresses) == 0) {
                    try {
                        $this->countVoidLookup();
                    } catch (DNSLookupException $e) {
                        return self::RESULT_PERMERROR;
                    }
                }
                if (isset($cidr)) {
                    foreach ($validIpAddresses as &$validIpAddress) {
                        $validIpAddress .= '/'.$cidr;
                    }
                }

                // CIDR 0 matches any IP Address
                if (isset($cidr) && $cidr == 0 && count($validIpAddresses) > 0) {
                    return $qualifier;
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
                if (isset($cidr) && !is_numeric($cidr)) {
                    // If cidr is not numeric, then it's not a cidr
                    // RFC 4408 allow any character, including /, in a domain name
                    $domain .= '/'.$cidr;
                    unset($cidr);
                }

                $validIpAddresses = array();
                $this->DNSRecordGetter->countRequest();
                $mxServers = $this->DNSRecordGetter->resolveMx($domain);
                if (count($mxServers) > 10) {
                    return self::RESULT_PERMERROR;
                }
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

                // CIDR 0 matches any IP Address
                if (isset($cidr) && $cidr == 0 && count($validIpAddresses) > 0) {
                    return $qualifier;
                }

                if (IpUtils::checkIp($ipAddress, $validIpAddresses)) {
                    return $qualifier;
                }
                break;

            case self::MECHANISM_PTR:
                $domain = $operand ? $operand : $matchingDomain;

                $this->DNSRecordGetter->countRequest();
                $ptrRecords                  = $this->DNSRecordGetter->resolvePtr($ipAddress);
                $validatedSendingDomainNames = array();
                foreach ($ptrRecords as $ptrRecord) {
                    $ptrRecord   = strtolower($ptrRecord);
                    $ipAddresses = $this->DNSRecordGetter->resolveA($ptrRecord);
                    if (in_array($ipAddress, $ipAddresses)) {
                        $validatedSendingDomainNames[] = $ptrRecord;
                    }
                }

                foreach ($validatedSendingDomainNames as $name) {
                    if ($name == $domain || substr($name, -strlen($domain)) == $domain) {
                        return $qualifier;
                    }
                }
                break;

            case self::MECHANISM_EXISTS:
                try {
                    if ($this->DNSRecordGetter->exists($operand)) {
                        return $qualifier;
                    }
                } catch (DNSLookupException $e) {
                    return self::RESULT_TEMPERROR;
                }
                break;

            case self::MECHANISM_INCLUDE:
                $this->DNSRecordGetter->countRequest();
                $includeResult = $this->doCheck($ipAddress, $operand);
                if (in_array($includeResult, array(self::RESULT_PASS, self::RESULT_DEFINITIVE_PERMERROR, self::RESULT_PERMERROR, self::RESULT_TEMPERROR))) {
                    return $includeResult;
                }
                if ($includeResult == self::RESULT_NONE) {
                    return self::RESULT_PERMERROR;
                }
                break;
            case self::MODIFIER_REDIRECT:
                $this->DNSRecordGetter->countRequest();
                $this->redirect = $operand;

                return false;
                break;
            case '':
                // If a SPF record contains multiple spaces between parts, this should not be considered as an unknown mechanism
                break;
            default:
                // This can't be a mechanism as we checked before if SPF syntax was correct (and mechanisms valid)
                // We are certain this is a modifier. Any string is allowed as a modifier, but that doesn't make it match
                return false;
                break;
        }

        return false;
    }

    private static function isSPFValid($spfRecord)
    {
        if (preg_match('/^v=spf1( +([-+?~]?(all|include:(%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}|%%|%_|%-|[!-$&-~])*(\.([A-Za-z]|[A-Za-z]([-0-9A-Za-z]?)*[0-9A-Za-z])|%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\})|a(:(%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}|%%|%_|%-|[!-$&-~])*(\.([A-Za-z]|[A-Za-z]([-0-9A-Za-z]?)*[0-9A-Za-z])|%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}))?((\/(\d|1\d|2\d|3[0-2]))?(\/\/([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8]))?)?|mx(:(%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}|%%|%_|%-|[!-$&-~])*(\.([A-Za-z]|[A-Za-z]([-0-9A-Za-z]?)*[0-9A-Za-z])|%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}))?((\/(\d|1\d|2\d|3[0-2]))?(\/\/([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8]))?)?|ptr(:(%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}|%%|%_|%-|[!-$&-~])*(\.([A-Za-z]|[A-Za-z]([-0-9A-Za-z]?)*[0-9A-Za-z])|%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}))?|ip4:([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|1[0-9]|2[0-9]|3[0-2]))?|ip6:(::|([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){1,8}:|([0-9A-Fa-f]{1,4}:){7}:[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}){1,2}|([0-9A-Fa-f]{1,4}:){5}(:[0-9A-Fa-f]{1,4}){1,3}|([0-9A-Fa-f]{1,4}:){4}(:[0-9A-Fa-f]{1,4}){1,4}|([0-9A-Fa-f]{1,4}:){3}(:[0-9A-Fa-f]{1,4}){1,5}|([0-9A-Fa-f]{1,4}:){2}(:[0-9A-Fa-f]{1,4}){1,6}|[0-9A-Fa-f]{1,4}:(:[0-9A-Fa-f]{1,4}){1,7}|:(:[0-9A-Fa-f]{1,4}){1,8}|([0-9A-Fa-f]{1,4}:){6}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|([0-9A-Fa-f]{1,4}:){6}:([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|([0-9A-Fa-f]{1,4}:){5}:([0-9A-Fa-f]{1,4}:)?([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|([0-9A-Fa-f]{1,4}:){4}:([0-9A-Fa-f]{1,4}:){0,2}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|([0-9A-Fa-f]{1,4}:){3}:([0-9A-Fa-f]{1,4}:){0,3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|([0-9A-Fa-f]{1,4}:){2}:([0-9A-Fa-f]{1,4}:){0,4}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|[0-9A-Fa-f]{1,4}::([0-9A-Fa-f]{1,4}:){0,5}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|::([0-9A-Fa-f]{1,4}:){0,6}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))(\/(\d{1,2}|10[0-9]|11[0-9]|12[0-8]))?|exists:(%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}|%%|%_|%-|[!-$&-~])*(\.([A-Za-z]|[A-Za-z]([-0-9A-Za-z]?)*[0-9A-Za-z])|%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}))|redirect=(%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}|%%|%_|%-|[!-$&-~])*(\.([A-Za-z]|[A-Za-z]([-0-9A-Za-z]?)*[0-9A-Za-z])|%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\})|exp=(%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}|%%|%_|%-|[!-$&-~])*(\.([A-Za-z]|[A-Za-z]([-0-9A-Za-z]?)*[0-9A-Za-z])|%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\})|[A-Za-z][-.0-9A-Z_a-z]*=(%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}|%%|%_|%-|[!-$&-~])*))* *$/i',
                $spfRecord) == 1
        ) {

            $recordParts = explode(' ', $spfRecord);
            array_shift($recordParts); // Remove first part (v=spf1)

            // RFC4408 6/2: each modifier can only appear once
            $redirectCount = 0;
            $expCount      = 0;
            foreach ($recordParts as $recordPart) {
                if (false !== strpos($recordPart, '=')) {
                    list($modifier, $domain) = explode('=', $recordPart, 2);
                    $expOrRedirect = false;
                    if ($modifier == self::MODIFIER_REDIRECT || substr($modifier, 1) == self::MODIFIER_REDIRECT) {
                        $redirectCount++;
                        $expOrRedirect = true;
                    }
                    if ($modifier == self::MODIFIER_EXP || substr($modifier, 1) == self::MODIFIER_EXP) {
                        $expCount++;
                        $expOrRedirect = true;
                    }
                    if ($expOrRedirect) {
                        if (empty($domain)) {
                            return false;
                        } else {
                            if (preg_match('/^[+-?~](all|a|mx|ptr|ip4|ip6|exists):?.*$/', $domain)) {
                                return false;
                            }
                            // @codeCoverageIgnoreStart
                            if (version_compare(PHP_VERSION, '7', '>=')) {
                                if (!filter_var($domain, FILTER_VALIDATE_DOMAIN)) {
                                    return false;
                                }
                            } else {
                                /** @link http://stackoverflow.com/a/4694816/2898156 */
                                if (!(preg_match('/^([_a-z\d](-*[a-z\d])*)(\.([a-z\d](-*[a-z\d])*))*$/i', $domain)
                                    && preg_match('/^.{1,253}$/', $domain)
                                    && preg_match('/^[^\.]{1,63}(\.[^\.]{1,63})*$/', $domain))
                                ) {
                                    return false;
                                }
                            }
                            // @codeCoverageIgnoreEnd
                        }
                    }
                }
            }
            if ($redirectCount > 1 || $expCount > 1) {
                return false;
            }

            return true;
        }

        return false;
    }

    protected function countVoidLookup()
    {
        if (++$this->voidLookup > 2) {
            throw new DNSLookupException();
        }
    }
}
