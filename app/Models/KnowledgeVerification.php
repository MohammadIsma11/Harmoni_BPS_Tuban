<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class KnowledgeVerification extends Model
{
    use HasFactory;

    protected $fillable = ['article_id', 'user_id', 'type', 'role_type'];

    public function article()
    {
        return $this->belongsTo(KnowledgeArticle::class, 'article_id');
    }

    public function user()
    {
        return $this->belongsTo(User::class, 'user_id');
    }
}
