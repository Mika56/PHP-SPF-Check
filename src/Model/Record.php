<?php

declare(strict_types=1);

namespace Mika56\SPFCheck\Model;

use Mika56\SPFCheck\Enum\Mechanism;
use Mika56\SPFCheck\Enum\Modifier as ModifierEnum;
use Mika56\SPFCheck\Enum\Qualifier;
use Mika56\SPFCheck\Mechanism\A;
use Mika56\SPFCheck\Mechanism\All;
use Mika56\SPFCheck\Mechanism\Exists;
use Mika56\SPFCheck\Mechanism\IncludeMechanism;
use Mika56\SPFCheck\Mechanism\IP;
use Mika56\SPFCheck\Mechanism\MX;
use Mika56\SPFCheck\Mechanism\PTR;
use Mika56\SPFCheck\Modifier\Explanation;
use Mika56\SPFCheck\Modifier\Redirect;

class Record
{
    private string $domainName;
    private string $rawRecord;

    public function __construct(string $domainName, string $rawRecord)
    {
        $this->domainName = $domainName;
        $this->rawRecord = $rawRecord;
    }

    public function getRawRecord(): string
    {
        return $this->rawRecord;
    }

    /**
     * @return Term[]
     */
    public function getTerms(): iterable
    {
        $terms = explode(' ', $this->rawRecord);
        array_shift($terms); // Remove first part (v=spf1)

        foreach ($terms as $term) {
            if(empty($term)) {
                continue;
            }
            preg_match('`^(?<qualifier>[+\-\~?])*?(?<term>[\w\-_\.]+)(?:(?<colonorequals>[:=])(?<domainnetwork>.+))?(?:/(?<cidr4>\d+)?(?://?(?<cidr6>\d+))?)?$`U', $term, $matches);
            if(!array_key_exists('qualifier', $matches) || empty($matches['qualifier'])) {
                $matches['qualifier'] = Qualifier::PASS;
            }
            $domainNetwork = array_key_exists('domainnetwork', $matches) && !empty($matches['domainnetwork']) ? $matches['domainnetwork'] : null;
            if(!empty($domainNetwork) && str_ends_with($domainNetwork, '.')) {
                $domainNetwork = substr($domainNetwork, 0, -1);
            }
            $cidr4 = array_key_exists('cidr4', $matches) && $matches['cidr4'] !== '' ? intval($matches['cidr4']) : null;
            $cidr6 = array_key_exists('cidr6', $matches) && $matches['cidr6'] !== '' ? intval($matches['cidr6']) : null;
            switch(strtolower($matches['term'])) {
                case Mechanism::ALL:
                    yield new All($term, $matches['qualifier']);
                    break;
                case Mechanism::IP4:
                    yield new IP($term, $matches['qualifier'], IP::VERSION_4, $domainNetwork, $cidr4);
                    break;
                case Mechanism::IP6:
                    // groups are named cidr4 and cidr6 for a/mx in order to support dual-cidr-length notation, but for ip4/ip6, there's always only one cidr
                    yield new IP($term, $matches['qualifier'], IP::VERSION_6, $domainNetwork, $cidr4);
                    break;
                case Mechanism::A:
                    yield new A($term, $matches['qualifier'], $domainNetwork ?? $this->domainName, $cidr4, $cidr6);
                    break;
                case Mechanism::MX:
                    yield new MX($term, $matches['qualifier'], $domainNetwork ?? $this->domainName, $cidr4, $cidr6);
                    break;
                case Mechanism::PTR:
                    yield new PTR($term, $matches['qualifier'], $domainNetwork ?? $this->domainName);
                    break;
                case Mechanism::EXISTS:
                    yield new Exists($term, $matches['qualifier'], $domainNetwork);
                    break;
                case Mechanism::INCLUDE:
                    yield new IncludeMechanism($term, $matches['qualifier'], $domainNetwork);
                    break;
                case ModifierEnum::REDIRECT:
                    yield new Redirect($term, $domainNetwork);
                    break;
                case ModifierEnum::EXP:
                    yield new Explanation($term, $domainNetwork);
                    break;
                default:
                    if($matches['colonorequals'] === '=') {
                        // "Unrecognized modifiers MUST be ignored no matter where in a record, or how often"
                        break;
                    }
                    throw new \LogicException('Unknown mechanism '.$matches['term']);
            }
        }
    }

    public function hasExplanation(): bool
    {
        return $this->getExplanation() !== null;
    }

    public function getExplanation(): ?Explanation
    {
        foreach ($this->getTerms() as $term) {
            if($term instanceof Explanation) {
                return $term;
            }
        }

        return null;
    }

    public function isValid(): bool
    {
        if(0 === preg_match('/^v=spf1( +([-+?~]?(all|include:(%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}|%%|%_|%-|[!-$&-~])*(\.([A-Za-z]|[A-Za-z]([-0-9A-Za-z]?)*[0-9A-Za-z])|%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\})\.?|a(:(%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}|%%|%_|%-|[!-$&-~])*(\.([A-Za-z]|[A-Za-z]([-0-9A-Za-z]?)*[0-9A-Za-z])|%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}))?((\/(\d|1\d|2\d|3[0-2]))?(\/\/(0|[1-9][0-9]?|10[0-9]|11[0-9]|12[0-8]))?)?|mx(:(%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}|%%|%_|%-|[!-$&-~])*(\.([A-Za-z]|[A-Za-z]([-0-9A-Za-z]?)*[0-9A-Za-z])|%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}))?((\/(\d|1\d|2\d|3[0-2]))?(\/\/(0|[1-9][0-9]?|10[0-9]|11[0-9]|12[0-8]))?)?|ptr(:(%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}|%%|%_|%-|[!-$&-~])*(\.([A-Za-z]|[A-Za-z]([-0-9A-Za-z]?)*[0-9A-Za-z])|%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}))?|ip4:([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|1[0-9]|2[0-9]|3[0-2]))?|ip6:(::|([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){1,8}:|([0-9A-Fa-f]{1,4}:){7}:[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}){1,2}|([0-9A-Fa-f]{1,4}:){5}(:[0-9A-Fa-f]{1,4}){1,3}|([0-9A-Fa-f]{1,4}:){4}(:[0-9A-Fa-f]{1,4}){1,4}|([0-9A-Fa-f]{1,4}:){3}(:[0-9A-Fa-f]{1,4}){1,5}|([0-9A-Fa-f]{1,4}:){2}(:[0-9A-Fa-f]{1,4}){1,6}|[0-9A-Fa-f]{1,4}:(:[0-9A-Fa-f]{1,4}){1,7}|:(:[0-9A-Fa-f]{1,4}){1,8}|([0-9A-Fa-f]{1,4}:){6}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|([0-9A-Fa-f]{1,4}:){6}:([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|([0-9A-Fa-f]{1,4}:){5}:([0-9A-Fa-f]{1,4}:)?([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|([0-9A-Fa-f]{1,4}:){4}:([0-9A-Fa-f]{1,4}:){0,2}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|([0-9A-Fa-f]{1,4}:){3}:([0-9A-Fa-f]{1,4}:){0,3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|([0-9A-Fa-f]{1,4}:){2}:([0-9A-Fa-f]{1,4}:){0,4}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|[0-9A-Fa-f]{1,4}::([0-9A-Fa-f]{1,4}:){0,5}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|::([0-9A-Fa-f]{1,4}:){0,6}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))(\/(\d{1,2}|10[0-9]|11[0-9]|12[0-8]))?|exists:(%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}|%%|%_|%-|[!-$&-~])*(\.([A-Za-z]|[A-Za-z]([-0-9A-Za-z]?)*[0-9A-Za-z])|%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}))|redirect=(%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}|%%|%_|%-|[!-$&-~])*(\.([A-Za-z]|[A-Za-z]([-0-9A-Za-z]?)*[0-9A-Za-z])|%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\})|exp=(%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}|%%|%_|%-|[!-$&-~])*(\.([A-Za-z]|[A-Za-z]([-0-9A-Za-z]?)*[0-9A-Za-z])|%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\})|[A-Za-z][-.0-9A-Z_a-z]*=(%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}|%%|%_|%-|[!-$&-~])*))* *$/i', $this->rawRecord)) {
            return false;
        }

        $recordParts = explode(' ', $this->rawRecord);
        array_shift($recordParts); // Remove first part (v=spf1)

        // RFC4408 6/2: each modifier can only appear once
        $redirectCount = 0;
        $expCount      = 0;
        foreach ($recordParts as $recordPart) {
            if (false === strpos($recordPart, '=')) {
                continue;
            }

            [$modifier, $domain] = explode('=', $recordPart, 2);
            $expOrRedirect = false;
            if ($modifier == ModifierEnum::REDIRECT || substr($modifier, 1) == ModifierEnum::REDIRECT) {
                $redirectCount++;
                $expOrRedirect = true;
            }
            if ($modifier == ModifierEnum::EXP || substr($modifier, 1) == ModifierEnum::EXP) {
                $expCount++;
                $expOrRedirect = true;
            }
            if ($expOrRedirect) {
                if (empty($domain)) {
                    return false;
                }
                else {
                    if (preg_match('/^[+-?~](all|a|mx|ptr|ip4|ip6|exists):?.*$/', $domain)) {
                        return false;
                    }
                    if(false===filter_var($domain, FILTER_VALIDATE_DOMAIN)) {
                        return false;
                    }
                }
            }
        }
        if ($redirectCount > 1 || $expCount > 1) {
            return false;
        }

        return true;
    }

}
