<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\Gate; 
use Illuminate\Support\Facades\View;
use Illuminate\Support\Facades\Auth;
use App\Models\User;
use App\Models\Agenda;
use App\Models\MeetingPresence;
use Illuminate\Support\Facades\URL;
use Illuminate\Pagination\Paginator;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        // 1. Gunakan Bootstrap 5 untuk Pagination
        Paginator::useBootstrapFive();

        // 2. Paksa HTTPS jika bukan di local (untuk fix 'Not Secure' alert di server)
        if (config('app.env') !== 'local') {
            URL::forceScheme('https');
        }

        // 2. GATE HAK AKSES (POV REVISI)
        Gate::define('is-admin', fn(User $user) => $user->role === 'Admin');
        Gate::define('is-not-admin', fn(User $user) => $user->role !== 'Admin');
        Gate::define('can-manage-ticket', function(\App\Models\User $user, \App\Models\Ticket $ticket) {
            if ($user->role === 'Admin' || $user->username === 'ketua.tim') return true;
            return is_array($ticket->assigned_to_ids) && in_array($user->id, $ticket->assigned_to_ids);
        });
        Gate::define('access-assignment', fn(User $user) => in_array($user->role, ['Kepala', 'Katim']));
        Gate::define('access-manajemen-user', fn(User $user) => in_array($user->role, ['Admin', 'Kepala']));
        Gate::define('is-pegawai', fn(User $user) => $user->role === 'Pegawai');
        
        Gate::define('access-absensi', function (User $user) {
            return $user->team && $user->team->nama_tim === 'Subbagian Umum';
        });

        Gate::define('access-mitra-rekap', function (User $user) {
            return in_array($user->role, ['Kepala', 'Katim', 'Admin']) || ($user->team && $user->team->nama_tim === 'Subbagian Umum');
        });


        // 3. LOGIKA NOTIFIKASI BADGE (View Composer - Optimized with Caching)
        View::composer('*', function ($view) {
            if (Auth::check()) {
                $user = Auth::user();
                $cacheKey = 'user_notif_counts_' . $user->id;

                $notifs = \Illuminate\Support\Facades\Cache::remember($cacheKey, 30, function() use ($user) {
                    // A. Hitung Tugas Lapangan (Tipe 1)
                    $countLapangan = Agenda::where('assigned_to', $user->id)
                        ->where('activity_type_id', 1)
                        ->where('status_laporan', 'Pending')
                        ->count();

                    // B. Hitung Kegiatan Dinas (Tipe 2 & 3)
                    $allKegiatanIds = Agenda::where('assigned_to', $user->id)
                        ->whereIn('activity_type_id', [2, 3])
                        ->where('status_laporan', 'Pending')
                        ->pluck('id');

                    $sudahAbsenCount = MeetingPresence::whereIn('agenda_id', $allKegiatanIds)
                        ->where('user_id', $user->id)
                        ->count();

                    return [
                        'notifLapangan' => $countLapangan,
                        'notifKegiatan' => $allKegiatanIds->count() - $sudahAbsenCount
                    ];
                });

                $view->with($notifs);
            }
        });
    }
}