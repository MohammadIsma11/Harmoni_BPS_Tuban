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
        Schema::table('agendas', function (Blueprint $table) {
            $table->string('kategori', 50)->nullable();
        });

        Schema::table('tematiks', function (Blueprint $table) {
            $table->string('kategori', 50)->default('Survei')->nullable();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('agendas', function (Blueprint $table) {
            $table->dropColumn('kategori');
        });

        Schema::table('tematiks', function (Blueprint $table) {
            $table->dropColumn('kategori');
        });
    }
};
