<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\Rule;

class ProfileController extends Controller
{
    public function edit()
    {
        return view('profile.edit', [
            'user' => Auth::user()
        ]);
    }

    public function update(Request $request)
    {
        /** @var \App\Models\User $user */
        $user = Auth::user();

        // --- 1. IDENTIFIKASI PEJABAT ASLI ---
        // Kita cek NIP atau Username Pejabat asli dari daftar Seeder.
        // Ini daftar username yang di Seeder kamu adalah Katim/Kepala.
        $daftarPejabat = [
            'kepala.bps', 'ketua.tim', 'dodik.hendarto', 'respati.yekti', 
            'umdatul.ummah', 'ika.rahmawati', 'arif.suroso', 'triana.puji', 
            'yudhi.prasetyono', 'wicaksono'
        ];

        // Cek apakah user yang login ini termasuk dalam daftar pejabat asli
        $isPejabatAsli = in_array($user->username, $daftarPejabat);

        // --- 2. LOGIKA ROLE YANG DIIZINKAN ---
        $allowedRoles = ['Pegawai'];

        // HANYA jika dia Pejabat Asli DAN menyalakan Akses Super (atau sedang menjabat), 
        // baru boleh ganti role.
        if ($isPejabatAsli && ($request->has_super_access == 1 || $user->role !== 'Pegawai')) {
            if ($user->team_id == 8) {
                $allowedRoles = ['Kepala', 'Pegawai'];
            } else {
                $allowedRoles = ['Katim', 'Pegawai'];
            }
        } 
        
        // Admin selalu Admin
        if ($user->role === 'Admin') {
            $allowedRoles = ['Admin'];
        }

        $request->validate([
            'nama_lengkap'     => 'required|string|max:255',
            'username'         => ['required', 'string', 'max:255', Rule::unique('users')->ignore($user->id)],
            'role'             => ['required', Rule::in($allowedRoles)],
            'password'         => 'nullable|min:8|confirmed',
        ]);

        // --- 3. UPDATE DATA DASAR ---
        $user->nama_lengkap = $request->nama_lengkap;
        $user->username = $request->username;

        // --- 4. LOGIKA AKSES SUPER (ANTI-NULL & TIKET BALIK) ---
        $hasSuper = $request->input('has_super_access', 0);

        // Jika dia Pejabat dan memilih balik jadi Kepala/Katim, PAKSA Akses Super aktif (1)
        if ($request->role === 'Kepala' || $request->role === 'Katim') {
            $hasSuper = 1;
        }

        // Simpan sebagai integer agar Postgres tidak error
        $user->has_super_access = (int) $hasSuper;

        // --- 5. UPDATE ROLE & PASSWORD ---
        if ($user->role !== 'Admin') {
            $user->role = $request->role;
        }

        if ($request->filled('password')) {
            $user->password = Hash::make($request->password);
        }

        $user->save();

        return back()->with('success', 'Profil berhasil diperbarui!');
    }
}