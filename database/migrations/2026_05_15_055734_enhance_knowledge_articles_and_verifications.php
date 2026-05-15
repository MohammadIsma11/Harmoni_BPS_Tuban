<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('knowledge_articles', function (Blueprint $table) {
            $table->foreignId('ticket_id')->nullable()->constrained('tickets')->nullOnDelete();
            $table->string('verification_status')->default('pending_kms'); // pending_kms, kms_approved, pending_public, public_approved
            $table->boolean('is_public')->default(false);
        });

        Schema::create('knowledge_verifications', function (Blueprint $table) {
            $table->id();
            $table->foreignId('article_id')->constrained('knowledge_articles')->cascadeOnDelete();
            $table->foreignId('user_id')->constrained('users')->cascadeOnDelete();
            $table->enum('type', ['kms', 'public']);
            $table->enum('role_type', ['specialist', 'staff']);
            $table->timestamps();

            $table->unique(['article_id', 'user_id', 'type']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('knowledge_verifications');
        Schema::table('knowledge_articles', function (Blueprint $table) {
            $table->dropColumn(['ticket_id', 'verification_status', 'is_public']);
        });
    }
};
