@extends('layouts.app')

@section('content')
<div class="container-fluid px-4 pb-5">
    {{-- Header Sederhana --}}
    <div class="mb-4 mt-4">
        <h4 class="fw-bold text-dark mb-1">Pengaturan Link Zoom</h4>
        <p class="text-muted small">Kelola link Zoom Meeting yang digunakan untuk layanan konsultasi online di halaman depan.</p>
    </div>

    <div class="row justify-content-center">
        <div class="col-lg-8">
            <div class="card border-0 shadow-sm rounded-4">
                <div class="card-body p-4 p-md-5">
                    
                    <h6 class="fw-bold text-dark mb-4 border-bottom pb-2">
                        <i class="fas fa-video me-2 text-primary"></i> Tautan Rapat Zoom
                    </h6>
                    
                    <form action="{{ route('admin.settings.zoom.update') }}" method="POST">
                        @csrf
                        
                        <div class="mb-4">
                            <label class="small fw-bold mb-2 text-dark">Link Zoom Meeting Baru</label>
                            <div class="input-group">
                                <span class="input-group-text bg-light border-0 rounded-start-3 text-muted" style="border-top-left-radius: 12px !important; border-bottom-left-radius: 12px !important;">
                                    <i class="fas fa-link"></i>
                                </span>
                                <input type="url" name="zoom_link" class="form-control bg-light border-0 @error('zoom_link') is-invalid @enderror" 
                                       placeholder="https://zoom.us/j/..." value="{{ old('zoom_link', $zoomLink) }}" required 
                                       style="border-top-right-radius: 12px !important; border-bottom-right-radius: 12px !important; padding: 12px 16px;">
                                @error('zoom_link') <div class="invalid-feedback">{{ $message }}</div> @enderror
                            </div>
                            <div class="form-text text-muted small mt-2">
                                <i class="fas fa-info-circle me-1"></i> Pastikan tautan lengkap dengan Meeting ID dan Password enkripsi (misal: <code>https://zoom.us/j/85755461223?pwd=...</code>) agar pengguna dapat langsung bergabung tanpa memasukkan password secara manual.
                            </div>
                        </div>

                        <div class="mb-4 p-3 border rounded-4 bg-primary bg-opacity-10 border-primary border-opacity-10">
                            <label class="small fw-bold d-block text-primary mb-1">
                                <i class="fas fa-eye me-1"></i> Tautan Aktif Saat Ini:
                            </label>
                            <a href="{{ $zoomLink }}" target="_blank" class="text-break small fw-semibold text-decoration-underline text-primary">
                                {{ $zoomLink }}
                            </a>
                        </div>

                        <div class="mt-4 pt-2">
                            <button type="submit" class="btn btn-primary rounded-pill px-5 py-2.5 fw-bold shadow-sm">
                                <i class="fas fa-save me-2"></i> Simpan Link Zoom
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>
@endsection
