<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * Laravel Model for SpfDnsCahce
 *
 * This implements the caching logic
 *
 * Copyright 2020 Rob Thomas <xrobau@gmail.com>
 *
 * @licence MIT
 * @package App\Models
 */
class SpfDnsCache extends Model
{
    protected $table = "spf_dns_cache";
    public $timestamps = false;

    private static $expiry = 'P1D';

    public static function lookup($domainname)
    {
        $parent = explode(".", $domainname, 2)[1] ?? $domainname;
        $r = self::whereRaw('validuntil > NOW()')
            ->where('domainname', '=', $domainname)
            ->orWhere(function ($q) use ($parent) {
                $q->where('parentdomain', '=', $parent)->where('iswildcard', '=', 1);
            })
            ->orderBy('txtrownum');
        return $r->get();
    }

    public static function getTxtRecords($domainname)
    {
        $all = self::lookup($domainname);
        $retarr = ["found" => count($all), "records" => []];
        foreach ($all as $row) {
            $retarr["records"][] = $row->txtvalue;
        }
        return $retarr;
    }

    public static function addEntry($domainname, array $txtrecords, $iswildcard = false, ?\DateInterval $expiry = null)
    {
        $parent = explode(".", $domainname, 2)[1] ?? $domainname;
        if (!$expiry) {
            $expiry = new \DateInterval(self::$expiry);
            $validuntil = (new \DateTimeImmutable())->add($expiry);
        }
        foreach ($txtrecords as $idx => $record) {
            $e = new self();
            $e->domainname = $domainname;
            $e->parentdomain = $parent;
            $e->iswildcard = $iswildcard;
            $e->validuntil = $validuntil;
            $e->txtrownum = $idx;
            $e->txtvalue = $record;
            $e->save();
        }
    }
}
