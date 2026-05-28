<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('assignment_reports', function (Blueprint $table) {
            $table->double('lat')->nullable()->after('file_dokumentasi');
            $table->double('lng')->nullable()->after('lat');
            $table->string('sls', 200)->nullable()->after('lng');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('assignment_reports', function (Blueprint $table) {
            $table->dropColumn(['lat', 'lng', 'sls']);
        });
    }
};
