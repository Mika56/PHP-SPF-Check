<?php

declare(strict_types=1);

namespace Mika56\SPFCheck;

use Mika56\SPFCheck\DNS\Session;
use Mika56\SPFCheck\Exception\MacroSyntaxError;
use Mika56\SPFCheck\Model\Query;

abstract class MacroUtils
{

    public static function truncateDomainName(string $domainName): string
    {
        while (strlen($domainName) > 253) {
            $domainName = substr($domainName, strpos($domainName, '.') + 1);
        }

        return $domainName;
    }

    /**
     * @param Session $DNSSession
     * @throws MacroSyntaxError
     */
    public static function expandMacro(string $macro, Query $query, Session $DNSSession, bool $isExplanation): string
    {
        $macro = str_replace(['%%', '%_', '%-'], ['%', ' ', '%20'], $macro);

        return preg_replace_callback('`%{(?<letter>[a-z])(?<digits>\d*)(?<reverse>r?)(?<delimiter>[.+,/_=-]*)}`i',
            function (array $matches) use ($query, $isExplanation, $DNSSession): string {
                $letter = strtolower($matches['letter']);
                switch ($letter) {
                    case 's': // <sender>
                        $result = $query->getSender();
                        break;
                    case 'l': // local-part of <sender>
                        [$result] = explode('@', $query->getSender(), 2);
                        if (empty($result)) {
                            $result = 'postmaster';
                        }
                        break;
                    case 'o': // domain of <sender>
                        [, $result] = explode('@', $query->getSender(), 2);
                        break;
                    case 'd': // <domain>
                        $result = $query->getOriginalDomainName() ?? $query->getDomainName();
                        break;
                    case 'i': // <ip>
                        if(str_contains($query->getIpAddress(), ':')) {
                            $result = strtoupper(self::expandIPv6($query->getIpAddress()));
                            $result = str_replace(':', '', $result);
                            $result = preg_replace('`([A-f0-9])`', '$1.', $result);
                            $result = substr($result, 0, -1);
                        }
                        else {
                            $result = $query->getIpAddress();
                        }
                        break;
                    case 'p': // the validated domain name of <ip>
                        $ptr = $DNSSession->resolvePTR($query->getIpAddress());
                        $result = 'unknown';
                        foreach ($ptr as $record) {
                            $result = $record;
                            break;
                        }
                        break;
                    case 'v': // the string "in-addr" if <ip> is ipv4, or "ip6" if <ip> is ipv6
                        $result = str_contains($query->getIpAddress(), ':') ? 'ip6' : 'in-addr';
                        break;
                    case 'h': // HELO/EHLO domain
                        $result = $query->getHelo();
                        break;
                    case 'c':
                        if (!$isExplanation) {
                            throw new MacroSyntaxError(true);
                        }
                        $result = strtolower($query->getIpAddress());
                        break;
                    case 'r':
                        if (!$isExplanation) {
                            throw new MacroSyntaxError(true);
                        }
                        $result = 'unknown';
                        break;
                    case 't':
                        if (!$isExplanation) {
                            throw new MacroSyntaxError(true);
                        }
                        $result = date('U');
                        break;
                    default:
                        throw new MacroSyntaxError(false, 'Unknown macro letter '.$letter);
                }

                $delimiters = !empty($matches['delimiter']) ? $matches['delimiter'] : '.';
                $result = preg_split('`['.$delimiters.']`', $result);

                if ($matches['reverse'] === 'r') {
                    $result = array_reverse($result);
                }

                if (is_numeric($matches['digits'])) {
                    $result = array_slice($result, -intval($matches['digits']));
                }
                $result = implode('.', $result);

                if (preg_match('`[A-Z]`', $matches['letter'])) {
                    $result = rawurlencode($result);
                }

                return $result;
            }, $macro);
    }

    public static function expandIPv6(string $ipAddress): string
    {
        $hex = unpack("H*hex", inet_pton($ipAddress));

        return substr(preg_replace('`([A-f0-9]{4})`', '$1:', $hex['hex']), 0, -1);
    }
}
