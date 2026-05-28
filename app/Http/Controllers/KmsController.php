<?php

namespace App\Http\Controllers;

use App\Models\KnowledgeArticle;
use App\Models\KnowledgeCategory;
use App\Models\KnowledgeApproval;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;

class KmsController extends Controller
{
    /**
     * PUBLIC: Home & Search
     */
    public function publicIndex(Request $request)
    {
        $query = KnowledgeArticle::query()->with('category');
        
        // Hanya tampilkan yang sudah benar-benar diverifikasi untuk Publik
        $query->where('verification_status', 'public_approved');
        
        if ($request->has('q')) {
            $query->where(function($q) use ($request) {
                $q->where('title', 'like', '%' . $request->q . '%')
                  ->orWhere('content', 'like', '%' . $request->q . '%');
            });
        }

        $articles = $query->latest()->paginate(9);
        
        // Counter kategori juga hanya menghitung yang Publik
        $categories = KnowledgeCategory::withCount(['articles' => function($q) {
            $q->where('verification_status', 'public_approved');
        }])->get();
        
        return view('kms.public.index', compact('articles', 'categories'));
    }

    /**
     * PUBLIC: View Article
     */
    public function show(KnowledgeArticle $article)
    {
        // Akses publik hanya untuk yang statusnya public_approved
        // Akses internal (pegawai login) untuk kms_approved ke atas
        if (Auth::check()) {
            if (!in_array($article->verification_status, ['kms_approved', 'pending_public', 'public_approved'])) {
                abort(404);
            }
        } else {
            if ($article->verification_status !== 'public_approved') {
                abort(404);
            }
        }

        $article->increment('view_count');
        return view('kms.public.show', compact('article'));
    }

    /**
     * ADMIN: List Articles for Management
     */
    public function adminIndex()
    {
        $articles = KnowledgeArticle::with(['category', 'author', 'verifications', 'ticket'])->latest()->paginate(10);
        return view('kms.admin.index', compact('articles'));
    }

    /**
     * ADMIN: Edit Article
     */
    public function edit(KnowledgeArticle $article)
    {
        $categories = KnowledgeCategory::all();
        return view('kms.admin.edit', compact('article', 'categories'));
    }

    /**
     * ADMIN: Update/Publish Article
     */
    public function update(Request $request, KnowledgeArticle $article)
    {
        $validated = $request->validate([
            'category_id' => 'required|exists:knowledge_categories,id',
            'title' => 'required|string|max:255',
            'content' => 'required|string',
            'tags' => 'nullable|string',
        ]);

        $validated['is_published'] = $request->boolean('is_published');

        $article->update($validated);

        return redirect()->route('kms.admin.index')->with('success', 'Artikel berhasil diperbarui.');
    }

    /**
     * ADMIN: Delete Article
     */
    public function destroy(KnowledgeArticle $article)
    {
        $article->delete();
        return redirect()->route('kms.admin.index')->with('success', 'Artikel berhasil dihapus.');
    }

    /**
     * VERIFY Article (KMS or Public)
     */
    public function verify(Request $request, KnowledgeArticle $article)
    {
        $user = Auth::user();
        $type = $request->input('type'); // 'kms' or 'public'

        // Determine if verifier is a specialist
        $isSpecialist = false;
        
        // 1. Check if Admin
        if ($user->role === 'Admin') $isSpecialist = true;
        
        // 2. Check if username is ketua.tim
        if ($user->username === 'ketua.tim') $isSpecialist = true;

        // 3. Check if PJ Kategori (if article linked to ticket)
        if ($article->ticket && $article->ticket->category) {
            $pjIds = $article->ticket->category->pj_ids ?? [];
            if (in_array($user->id, $pjIds)) $isSpecialist = true;
        }

        $roleType = $isSpecialist ? 'specialist' : 'staff';

        // Check if already verified by this user for this type
        $existing = \App\Models\KnowledgeVerification::where('article_id', $article->id)
            ->where('user_id', $user->id)
            ->where('type', $type)
            ->first();

        if ($existing) {
            return redirect()->back()->with('error', 'Anda sudah melakukan verifikasi untuk tahap ini.');
        }

        \App\Models\KnowledgeVerification::create([
            'article_id' => $article->id,
            'user_id' => $user->id,
            'type' => $type,
            'role_type' => $roleType
        ]);

        // Refresh article to check conditions
        $article->load('verifications');

        if ($type === 'kms' && $article->isApprovedForKms()) {
            $status = 'kms_approved';
            if ($request->has('propose_public') && $request->propose_public == 1) {
                $status = 'pending_public';
            }
            $article->update(['verification_status' => $status]);
        } elseif ($type === 'public' && $article->isApprovedForPublic()) {
            $article->update([
                'verification_status' => 'public_approved',
                'is_public' => true,
                'is_published' => true
            ]);
        }

        return redirect()->back()->with('success', 'Verifikasi Anda berhasil disimpan.');
    }

    /**
     * Request Public Publication
     */
    public function requestPublic(KnowledgeArticle $article)
    {
        \Illuminate\Support\Facades\Log::info('requestPublic started for article ' . $article->id);
        
        if ($article->verification_status !== 'kms_approved') {
            return redirect()->back()->with('error', 'Artikel harus disetujui masuk KMS terlebih dahulu.');
        }

        $article->update(['verification_status' => 'pending_public']);
        \Illuminate\Support\Facades\Log::info('requestPublic update finished');

        return redirect()->back()->with('success', 'Permintaan publikasi ke publik berhasil diajukan.');
    }

    /**
     * Submit feedback for an article (Helpful/Unhelpful)
     */
    public function feedback(Request $request, KnowledgeArticle $article)
    {
        $request->validate([
            'type' => 'required|in:helpful,not_helpful'
        ]);

        $sessionKey = 'kms_article_feedback_' . $article->id;

        if (session()->has($sessionKey)) {
            return response()->json([
                'success' => false,
                'message' => 'Anda sudah memberikan masukan untuk artikel ini.'
            ], 400);
        }

        if ($request->type === 'helpful') {
            $article->increment('helpful_count');
        } else {
            $article->increment('not_helpful_count');
        }

        session()->put($sessionKey, $request->type);

        return response()->json([
            'success' => true,
            'message' => 'Terima kasih atas masukan Anda!',
            'helpful_count' => $article->helpful_count,
            'not_helpful_count' => $article->not_helpful_count
        ]);
    }
}
