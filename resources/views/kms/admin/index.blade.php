@extends('layouts.app')

@section('content')
<div class="container-fluid px-4 py-4">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <div>
            <h2 class="fw-bold text-dark mb-1">Knowledge Management System (KMS)</h2>
            <p class="text-muted">Kelola artikel pengetahuan dan proses verifikasi publikasi.</p>
        </div>
    </div>

    <div class="card border-0 shadow-sm rounded-4">
        <div class="card-body p-0">
            <div class="table-responsive">
                <table class="table table-hover align-middle mb-0">
                    <thead class="bg-light text-muted small text-uppercase fw-bold">
                        <tr>
                            <th class="px-4 py-3" style="width: 12%">Ticket ID</th>
                            <th class="py-3" style="width: 18%">Judul</th>
                            <th class="py-3" style="width: 20%">Deskripsi Masalah</th>
                            <th class="py-3" style="width: 12%">Kategori</th>
                            <th class="py-3" style="width: 12%">Status</th>
                            <th class="py-3" style="width: 12%">Tag</th>
                            <th class="py-3 text-center" style="width: 4%">Views</th>
                            <th class="py-3 text-end px-4" style="width: 10%">Aksi</th>
                        </tr>
                    </thead>
                    <tbody>
                        @forelse($articles as $article)
                        <tr>
                            <td class="px-4 py-4">
                                @if($article->ticket)
                                    <span class="fw-bold text-primary" style="font-size: 0.85rem;">
                                        {{ $article->ticket->tracking_id }}
                                    </span>
                                @else
                                    <span class="text-muted italic small">-</span>
                                @endif
                            </td>
                            <td class="py-4">
                                <div class="fw-bold text-dark">{{ $article->title }}</div>
                            </td>
                            <td class="py-4">
                                <div class="small text-muted" style="max-height: 60px; overflow: hidden; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical;">
                                    {{ strip_tags($article->content) }}
                                </div>
                            </td>
                            <td class="py-4">
                                <span class="badge bg-light text-dark border rounded-pill px-3 py-2">
                                    {{ $article->category->name }}
                                </span>
                            </td>
                            <td class="py-4">
                                @php
                                    $statusConfig = [
                                        'pending_kms' => ['class' => 'warning', 'label' => 'Pending KMS'],
                                        'kms_approved' => ['class' => 'info', 'label' => 'Internal'],
                                        'pending_public' => ['class' => 'primary', 'label' => 'Pending Pub'],
                                        'public_approved' => ['class' => 'success', 'label' => 'Public'],
                                    ][$article->verification_status] ?? ['class' => 'secondary', 'label' => 'Unknown'];
                                @endphp
                                <span class="badge bg-{{ $statusConfig['class'] }} rounded-pill px-3 py-2" style="font-size: 0.7rem;">
                                    {{ strtoupper($statusConfig['label']) }}
                                </span>
                            </td>
                            <td class="py-4">
                                @if($article->tags)
                                    @php $tags = explode(',', $article->tags); @endphp
                                    @foreach(array_slice($tags, 0, 2) as $tag)
                                        <span class="badge bg-light text-primary border rounded-pill small px-2 mb-1" style="font-size: 0.65rem; font-weight: 500;">
                                            {{ trim($tag) }}
                                        </span>
                                    @endforeach
                                @else
                                    <span class="text-muted small">-</span>
                                @endif
                            </td>
                            <td class="py-4 text-center">
                                <span class="fw-bold">{{ $article->view_count }}</span>
                            </td>
                            <td class="text-end px-4">
                                <div class="dropdown">
                                    <button class="btn btn-light btn-sm rounded-circle border shadow-sm" type="button" data-bs-toggle="dropdown" data-bs-display="static" aria-expanded="false" style="width: 32px; height: 32px; padding: 0;">
                                        <i class="fas fa-ellipsis-v"></i>
                                    </button>
                                    <ul class="dropdown-menu dropdown-menu-end shadow-lg border-0 rounded-3" style="min-width: 180px; z-index: 1050;">
                                        {{-- Verification Actions --}}
                                        @if($article->verification_status === 'pending_kms')
                                            <li>
                                                <button type="button" class="dropdown-item text-warning py-2 btn-open-verify" 
                                                    data-id="{{ $article->id }}"
                                                    data-title="{{ $article->title }}"
                                                    {{ $article->verifications->where('user_id', Auth::id())->where('type', 'kms')->count() ? 'disabled' : '' }}>
                                                    <i class="fas fa-check-circle me-2"></i>Verifikasi KMS
                                                </button>
                                            </li>
                                        @elseif($article->verification_status === 'kms_approved')
                                            <li>
                                                <form action="{{ route('kms.admin.request-public', $article->id) }}" method="POST">
                                                    @csrf
                                                    <button type="submit" class="dropdown-item text-primary py-2">
                                                        <i class="fas fa-globe me-2"></i>Ajukan Publik
                                                    </button>
                                                </form>
                                            </li>
                                        @elseif($article->verification_status === 'pending_public')
                                            <li>
                                                <form action="{{ route('kms.admin.verify', $article->id) }}" method="POST">
                                                    @csrf
                                                    <input type="hidden" name="type" value="public">
                                                    <button type="submit" class="dropdown-item text-success py-2"
                                                        {{ $article->verifications->where('user_id', Auth::id())->where('type', 'public')->count() ? 'disabled' : '' }}>
                                                        <i class="fas fa-bullhorn me-2"></i>Verifikasi Publik
                                                    </button>
                                                </form>
                                            </li>
                                        @endif
                                        
                                        <li><hr class="dropdown-divider"></li>
                                        <li>
                                            <a class="dropdown-item py-2" href="{{ route('kms.public.show', $article->slug) }}" target="_blank">
                                                <i class="fas fa-eye me-2 text-info"></i>Lihat Artikel
                                            </a>
                                        </li>
                                        <li>
                                            <a class="dropdown-item py-2" href="{{ route('kms.admin.edit', $article->id) }}">
                                                <i class="fas fa-edit me-2 text-primary"></i>Edit
                                            </a>
                                        </li>
                                        <li>
                                            <form action="{{ route('kms.admin.destroy', $article->id) }}" method="POST" class="form-delete-article">
                                                @csrf
                                                @method('DELETE')
                                                <button type="button" class="dropdown-item text-danger py-2 btn-delete-confirm">
                                                    <i class="fas fa-trash me-2"></i>Hapus
                                                </button>
                                            </form>
                                        </li>
                                    </ul>
                                </div>
                            </td>
                        </tr>
                        @empty
                        <tr>
                            <td colspan="8" class="text-center py-5 text-muted italic">
                                Belum ada artikel penugasan KMS.
                            </td>
                        </tr>
                        @endforelse
                    </tbody>
                </table>
            </div>
            <div class="p-4 border-top">
                {{ $articles->links() }}
            </div>
        </div>
    </div>

@push('modals')
    {{-- Modal Verifikasi KMS --}}
    <div class="modal fade" id="modalVerifyKms" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content border-0 shadow-lg rounded-4">
                <div class="modal-header border-0 p-4 pb-0">
                    <h5 class="modal-title fw-bold">Verifikasi Artikel KMS</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <form id="formVerifyKms" action="" method="POST">
                    @csrf
                    <input type="hidden" name="type" value="kms">
                    <div class="modal-body p-4">
                        <p class="text-muted mb-4">Apakah Anda menyetujui artikel <strong id="verify-title"></strong> untuk masuk ke sistem KMS?</p>
                        
                        <div class="bg-light p-3 rounded-4 mb-2">
                            <label class="form-label fw-bold small text-uppercase text-primary mb-3 d-block">Opsi Publikasi</label>
                            <div class="form-check mb-3">
                                <input class="form-check-input" type="radio" name="propose_public" id="opt_internal" value="0" checked>
                                <label class="form-check-label" for="opt_internal" role="button">
                                    <span class="fw-bold d-block">Hanya Internal</span>
                                    <span class="small text-muted">Artikel hanya dapat dilihat oleh pegawai yang sudah login.</span>
                                </label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="radio" name="propose_public" id="opt_public" value="1">
                                <label class="form-check-label" for="opt_public" role="button">
                                    <span class="fw-bold d-block">Ajukan ke Publik</span>
                                    <span class="small text-muted">Artikel akan diproses untuk publikasi ke masyarakat umum.</span>
                                </label>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer border-0 p-4 pt-0">
                        <button type="button" class="btn btn-light rounded-pill px-4" data-bs-dismiss="modal">Batal</button>
                        <button type="submit" class="btn btn-warning rounded-pill px-4 fw-bold">Simpan Verifikasi</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
@endpush
</div>
@endsection

@push('styles')
<style>
    .btn-xs {
        padding: 0.25rem 0.5rem;
        font-size: 0.7rem;
        line-height: 1;
        border-radius: 0.2rem;
    }
    .table th {
        font-size: 0.75rem;
        letter-spacing: 0.05em;
    }
    .badge {
        font-weight: 600;
    }
    /* Fix for dropdown in responsive table */
    .table-responsive {
        overflow: visible !important;
    }
</style>
@endpush

@push('scripts')
<script>
    $(document).ready(function() {
        $('.btn-open-verify').on('click', function() {
            const id = $(this).data('id');
            const title = $(this).data('title');
            const url = "{{ route('kms.admin.verify', ':id') }}".replace(':id', id);
            
            $('#formVerifyKms').attr('action', url);
            $('#verify-title').text(title);
            $('#modalVerifyKms').modal('show');
        });

        $('.btn-delete-confirm').on('click', function() {
            const form = $(this).closest('form');
            Swal.fire({
                title: 'Hapus Artikel?',
                text: "Artikel yang dihapus tidak dapat dikembalikan!",
                icon: 'warning',
                showCancelButton: true,
                confirmButtonColor: '#dc3545',
                cancelButtonColor: '#6c757d',
                confirmButtonText: 'Ya, Hapus!',
                cancelButtonText: 'Batal',
                reverseButtons: true
            }).then((result) => {
                if (result.isConfirmed) {
                    form.submit();
                }
            });
        });
    });
</script>
@endpush
