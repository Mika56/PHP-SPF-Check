<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Laravel Migration to create SPF DNS Cache
 *
 * Copyright 2020 Rob Thomas <xrobau@gmail.com>
 *
 * @licence MIT
 */
class CreateSpfDnsCache extends Migration
{
    /**
     * Create our dns cache table
     *
     * @return void
     */
    public function up()
    {
        Schema::create('spf_dns_cache', function (Blueprint $table) {
            $table->bigIncrements('id');
            $table->dateTime('validuntil');
            $table->char('domainname', 200);
            $table->char('parentdomain');
            $table->boolean('iswildcard')->default(0);
            $table->integer('txtrownum')->default(0);
            $table->text('txtvalue');
            $table->index(['domainname', 'parentdomain', 'iswildcard', 'validuntil'], 'mainidx');
            $table->index('validuntil');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('spf_dns_cache');
    }
}
