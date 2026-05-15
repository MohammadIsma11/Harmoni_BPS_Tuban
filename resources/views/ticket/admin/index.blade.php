@extends('layouts.app')

@section('content')
<div class="container-fluid px-4">
    <div class="d-flex align-items-center justify-content-between mb-4">
        <div>
            <h3 class="fw-bold text-dark mb-1">Manajemen Tiket IT</h3>
            <p class="text-muted small">Kelola laporan kendala IT dari internal maupun masyarakat.</p>
        </div>
        <div class="d-flex gap-2">
            <a href="{{ route('ticket.public.create') }}" target="_blank" class="btn btn-outline-primary rounded-pill px-4 fw-bold">
                <i class="fas fa-plus me-2"></i>Buat Baru
            </a>
        </div>
    </div>

    <div class="card border-0 shadow-sm rounded-4 mb-4">
        <div class="card-body p-3">
            <form action="{{ route('ticket.admin.index') }}" method="GET" class="row g-2 align-items-center">
                <div class="col-md-4">
                    <div class="input-group">
                        <span class="input-group-text bg-white border-light text-muted"><i class="fas fa-search"></i></span>
                        <input type="text" name="search" class="form-control border-light" placeholder="Cari Subjek, ID, atau Pelapor..." value="{{ request('search') }}">
                    </div>
                </div>
                <div class="col-md-3">
                    <select name="category_id" class="form-select border-light">
                        <option value="">Semua Kategori</option>
                        @foreach($categories as $cat)
                            <option value="{{ $cat->id }}" {{ request('category_id') == $cat->id ? 'selected' : '' }}>{{ $cat->name }}</option>
                        @endforeach
                    </select>
                </div>
                <div class="col-md-2">
                    <select name="status" class="form-select border-light">
                        <option value="">Semua Status</option>
                        <option value="open" {{ request('status') == 'open' ? 'selected' : '' }}>Open</option>
                        <option value="assigned" {{ request('status') == 'assigned' ? 'selected' : '' }}>Assigned</option>
                        <option value="onprogress" {{ request('status') == 'onprogress' ? 'selected' : '' }}>Progress</option>
                        <option value="check wa" {{ request('status') == 'check wa' ? 'selected' : '' }}>Check WA</option>
                        <option value="closed" {{ request('status') == 'closed' ? 'selected' : '' }}>Closed</option>
                    </select>
                </div>
                <div class="col-md-3 d-flex gap-2">
                    <button type="submit" class="btn btn-primary rounded-pill flex-grow-1 px-4 fw-bold shadow-sm">
                        <i class="fas fa-filter me-2"></i>Filter
                    </button>
                    @if(request()->anyFilled(['search', 'category_id', 'status']))
                        <a href="{{ route('ticket.admin.index') }}" class="btn btn-light rounded-pill px-4" title="Reset Filter">
                            <i class="fas fa-undo"></i>
                        </a>
                    @endif
                </div>
            </form>
        </div>
    </div>

    <div class="row g-3 mb-4">
        @php
            $statsCards = [
                ['label' => 'Total Tiket', 'count' => $stats['total'], 'icon' => 'fa-ticket-alt', 'color' => 'primary'],
                ['label' => 'Open', 'count' => $stats['open'], 'icon' => 'fa-envelope-open', 'color' => 'warning'],
                ['label' => 'Assigned', 'count' => $stats['assigned'], 'icon' => 'fa-user-tag', 'color' => 'info'],
                ['label' => 'On Progress', 'count' => $stats['onprogress'], 'icon' => 'fa-spinner', 'color' => 'primary'],
                ['label' => 'Check WA', 'count' => $stats['check wa'], 'icon' => 'fa-comment-alt', 'color' => 'success'],
                ['label' => 'Closed', 'count' => $stats['closed'], 'icon' => 'fa-check-circle', 'color' => 'secondary'],
            ];
        @endphp
        @foreach($statsCards as $s)
        <div class="col-md-2" style="flex: 1;">
            <div class="card border-0 shadow-sm rounded-4 p-3 h-100">
                <div class="d-flex align-items-center justify-content-between">
                    <div>
                        <div class="small text-muted fw-bold text-uppercase mb-1" style="font-size: 0.6rem;">{{ $s['label'] }}</div>
                        <h4 class="fw-bold mb-0">{{ $s['count'] }}</h4>
                    </div>
                    <div class="rounded-3 p-2 d-flex align-items-center justify-content-center" style="background-color: rgba({{ $s['color'] == 'primary' ? '13, 110, 253' : ($s['color'] == 'warning' ? '255, 193, 7' : ($s['color'] == 'info' ? '13, 202, 240' : ($s['color'] == 'success' ? '25, 135, 84' : '108, 117, 125'))) }}, 0.1); color: var(--bs-{{ $s['color'] }});">
                        <i class="fas {{ $s['icon'] }} fs-5"></i>
                    </div>
                </div>
            </div>
        </div>
        @endforeach
    </div>

    <div class="card border-0 shadow-sm rounded-4 overflow-hidden">
        <div class="table-responsive">
            <table class="table table-hover align-middle mb-0">
                <thead class="bg-light">
                    <tr>
                        <th class="ps-4 py-3 text-muted small fw-bold">TIKET & PELAPOR</th>
                        <th class="py-3 text-muted small fw-bold">KATEGORI</th>
                        <th class="py-3 text-muted small fw-bold">DESKRIPSI</th>
                        <th class="py-3 text-muted small fw-bold text-center">STATUS</th>
                        <th class="py-3 text-muted small fw-bold">PJ / ASSIGNEE</th>
                        <th class="pe-4 py-3 text-muted small fw-bold text-end">AKSI</th>
                    </tr>
                </thead>
                <tbody>
                    @forelse($tickets as $ticket)
                    <tr>
                        <td class="ps-4">
                            <div class="fw-bold text-dark">{{ $ticket->subject }}</div>
                            <div class="d-flex align-items-center mt-1">
                                <span class="badge bg-primary bg-opacity-10 text-primary rounded-pill me-2" style="font-size: 0.65rem;">{{ $ticket->tracking_id }}</span>
                                <small class="text-muted">{{ $ticket->reporter_name }}</small>
                            </div>
                        </td>
                        <td>
                            <div class="small text-dark fw-bold">{{ $ticket->category->name }}</div>
                            <div class="small text-muted" style="font-size: 0.65rem;">{{ $ticket->reporter_organization }}</div>
                        </td>
                        <td>
                            <div class="small text-muted" style="max-width: 200px; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden;">
                                {{ strip_tags($ticket->description) }}
                            </div>
                        </td>
                        <td class="text-center">
                            @php
                                $statusMap = [
                                    'open' => ['color' => 'warning', 'label' => 'OPEN'],
                                    'assigned' => ['color' => 'info', 'label' => 'ASSIGNED'],
                                    'onprogress' => ['color' => 'primary', 'label' => 'PROGRESS'],
                                    'check wa' => ['color' => 'success', 'label' => 'CHECK WA'],
                                    'closed' => ['color' => 'secondary', 'label' => 'CLOSED']
                                ];
                                $st = $statusMap[$ticket->status] ?? ['color' => 'secondary', 'label' => $ticket->status];
                            @endphp
                            <span class="badge bg-{{ $st['color'] }} rounded-pill px-3 py-2 fw-bold shadow-sm" style="font-size: 0.65rem;">
                                {{ $st['label'] }}
                            </span>
                        </td>
                        <td>
                            @php
                                $ids = $ticket->assigned_to_ids ?? [];
                            @endphp
                            @forelse($ids as $id)
                                <span class="badge bg-light text-dark border rounded-pill small mb-1" style="font-size: 0.6rem;">{{ $assigneeNames[$id] ?? 'Unknown' }}</span>
                            @empty
                                <span class="text-muted small italic" style="font-size: 0.6rem;">Belum ditugaskan</span>
                            @endforelse
                        </td>
                        <td class="pe-4 text-end">
                            <div class="d-flex gap-1 justify-content-end">
                                @if($ticket->status === 'closed' && !$ticket->pushed_to_kms)
                                    <form action="{{ route('ticket.admin.push', $ticket->id) }}" method="POST" class="form-push-kms">
                                        @csrf
                                        <button type="button" class="btn btn-primary btn-sm rounded-pill px-3 btn-push-confirm" title="Push ke KMS">
                                            <i class="fas fa-share-square me-1"></i> Push
                                        </button>
                                    </form>
                                @elseif($ticket->status === 'closed' && $ticket->pushed_to_kms)
                                    <span class="badge bg-success text-white rounded-pill px-3 py-2 shadow-sm" style="font-size: 0.65rem;">
                                        <i class="fas fa-check-double me-1"></i> Pushed
                                    </span>
                                @endif
                                <a href="{{ route('ticket.admin.show', $ticket->id) }}" class="btn btn-outline-primary btn-sm rounded-pill px-3">
                                    <i class="fas fa-eye me-1"></i> Detail
                                </a>
                                <form action="{{ route('ticket.admin.destroy', $ticket->id) }}" method="POST" class="form-delete-ticket">
                                    @csrf
                                    @method('DELETE')
                                    <button type="button" class="btn btn-outline-danger btn-sm rounded-pill px-3 btn-delete-ticket" title="Hapus Tiket">
                                        <i class="fas fa-trash"></i>
                                    </button>
                                </form>
                            </div>
                        </td>
                    </tr>
                    @empty
                    <tr>
                        <td colspan="5" class="text-center py-5 text-muted">
                            <i class="fas fa-inbox fs-1 d-block mb-3 opacity-25"></i>
                            Belum ada tiket yang masuk.
                        </td>
                    </tr>
                    @endforelse
                </tbody>
            </table>
        </div>
        @if($tickets->hasPages())
        <div class="p-4 border-top">
            {{ $tickets->links() }}
        </div>
        @endif
    </div>
</div>
@endsection

@push('scripts')
<script>
    $(document).ready(function() {
        $('.btn-push-confirm').on('click', function() {
            const form = $(this).closest('form');
            Swal.fire({
                title: 'Push ke KMS?',
                text: "Solusi tiket ini akan dibagikan ke Knowledge Management System.",
                icon: 'question',
                showCancelButton: true,
                confirmButtonColor: '#0058a8',
                cancelButtonColor: '#6c757d',
                confirmButtonText: 'Ya, Push Sekarang!',
                cancelButtonText: 'Batal',
                reverseButtons: true
            }).then((result) => {
                if (result.isConfirmed) {
                    form.submit();
                }
            });
        });

        $('.btn-delete-ticket').on('click', function() {
            const form = $(this).closest('form');
            Swal.fire({
                title: 'Hapus Tiket?',
                text: "Data tiket dan riwayat percakapan akan dihapus permanen!",
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
