<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class KnowledgeArticle extends Model
{
    use HasFactory;

    protected $fillable = [
        'category_id', 'author_id', 'ticket_id', 'title', 'slug', 
        'content', 'view_count', 'is_published', 'verification_status', 'is_public', 'tags',
        'helpful_count', 'not_helpful_count'
    ];

    public function category()
    {
        return $this->belongsTo(KnowledgeCategory::class, 'category_id');
    }

    public function author()
    {
        return $this->belongsTo(User::class, 'author_id');
    }

    public function ticket()
    {
        return $this->belongsTo(Ticket::class, 'ticket_id');
    }

    public function verifications()
    {
        return $this->hasMany(KnowledgeVerification::class, 'article_id');
    }

    public function approval()
    {
        return $this->hasOne(KnowledgeApproval::class, 'article_id');
    }

    /**
     * Check if article is approved for KMS admission
     */
    public function isApprovedForKms()
    {
        return $this->hasConditionMet('kms');
    }

    /**
     * Check if article is approved for Public publication
     */
    public function isApprovedForPublic()
    {
        return $this->hasConditionMet('public');
    }

    private function hasConditionMet($type)
    {
        $verifications = $this->verifications()->where('type', $type)->get();
        
        $specialistCount = $verifications->where('role_type', 'specialist')->count();
        $staffCount = $verifications->where('role_type', 'staff')->count();

        return ($specialistCount >= 1) || ($staffCount >= 2);
    }
}
