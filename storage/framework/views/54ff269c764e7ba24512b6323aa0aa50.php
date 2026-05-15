<?php $__env->startSection('content'); ?>
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
                        <?php $__empty_1 = true; $__currentLoopData = $articles; $__env->addLoop($__currentLoopData); foreach($__currentLoopData as $article): $__env->incrementLoopIndices(); $loop = $__env->getLastLoop(); $__empty_1 = false; ?>
                        <tr>
                            <td class="px-4 py-4">
                                <?php if($article->ticket): ?>
                                    <span class="fw-bold text-primary" style="font-size: 0.85rem;">
                                        <?php echo e($article->ticket->tracking_id); ?>

                                    </span>
                                <?php else: ?>
                                    <span class="text-muted italic small">-</span>
                                <?php endif; ?>
                            </td>
                            <td class="py-4">
                                <div class="fw-bold text-dark"><?php echo e($article->title); ?></div>
                            </td>
                            <td class="py-4">
                                <div class="small text-muted" style="max-height: 60px; overflow: hidden; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical;">
                                    <?php echo e(strip_tags($article->content)); ?>

                                </div>
                            </td>
                            <td class="py-4">
                                <span class="badge bg-light text-dark border rounded-pill px-3 py-2">
                                    <?php echo e($article->category->name); ?>

                                </span>
                            </td>
                            <td class="py-4">
                                <?php
                                    $statusConfig = [
                                        'pending_kms' => ['class' => 'warning', 'label' => 'Pending KMS'],
                                        'kms_approved' => ['class' => 'info', 'label' => 'Internal'],
                                        'pending_public' => ['class' => 'primary', 'label' => 'Pending Pub'],
                                        'public_approved' => ['class' => 'success', 'label' => 'Public'],
                                    ][$article->verification_status] ?? ['class' => 'secondary', 'label' => 'Unknown'];
                                ?>
                                <span class="badge bg-<?php echo e($statusConfig['class']); ?> rounded-pill px-3 py-2" style="font-size: 0.7rem;">
                                    <?php echo e(strtoupper($statusConfig['label'])); ?>

                                </span>
                            </td>
                            <td class="py-4">
                                <?php if($article->tags): ?>
                                    <?php $tags = explode(',', $article->tags); ?>
                                    <?php $__currentLoopData = array_slice($tags, 0, 2); $__env->addLoop($__currentLoopData); foreach($__currentLoopData as $tag): $__env->incrementLoopIndices(); $loop = $__env->getLastLoop(); ?>
                                        <span class="badge bg-light text-primary border rounded-pill small px-2 mb-1" style="font-size: 0.65rem; font-weight: 500;">
                                            <?php echo e(trim($tag)); ?>

                                        </span>
                                    <?php endforeach; $__env->popLoop(); $loop = $__env->getLastLoop(); ?>
                                <?php else: ?>
                                    <span class="text-muted small">-</span>
                                <?php endif; ?>
                            </td>
                            <td class="py-4 text-center">
                                <span class="fw-bold"><?php echo e($article->view_count); ?></span>
                            </td>
                            <td class="text-end px-4">
                                <div class="dropdown">
                                    <button class="btn btn-light btn-sm rounded-circle border shadow-sm" type="button" data-bs-toggle="dropdown" data-bs-display="static" aria-expanded="false" style="width: 32px; height: 32px; padding: 0;">
                                        <i class="fas fa-ellipsis-v"></i>
                                    </button>
                                    <ul class="dropdown-menu dropdown-menu-end shadow-lg border-0 rounded-3" style="min-width: 180px; z-index: 1050;">
                                        
                                        <?php if($article->verification_status === 'pending_kms'): ?>
                                            <li>
                                                <button type="button" class="dropdown-item text-warning py-2 btn-open-verify" 
                                                    data-id="<?php echo e($article->id); ?>"
                                                    data-title="<?php echo e($article->title); ?>"
                                                    <?php echo e($article->verifications->where('user_id', Auth::id())->where('type', 'kms')->count() ? 'disabled' : ''); ?>>
                                                    <i class="fas fa-check-circle me-2"></i>Verifikasi KMS
                                                </button>
                                            </li>
                                        <?php elseif($article->verification_status === 'kms_approved'): ?>
                                            <li>
                                                <form action="<?php echo e(route('kms.admin.request-public', $article->id)); ?>" method="POST">
                                                    <?php echo csrf_field(); ?>
                                                    <button type="submit" class="dropdown-item text-primary py-2">
                                                        <i class="fas fa-globe me-2"></i>Ajukan Publik
                                                    </button>
                                                </form>
                                            </li>
                                        <?php elseif($article->verification_status === 'pending_public'): ?>
                                            <li>
                                                <form action="<?php echo e(route('kms.admin.verify', $article->id)); ?>" method="POST">
                                                    <?php echo csrf_field(); ?>
                                                    <input type="hidden" name="type" value="public">
                                                    <button type="submit" class="dropdown-item text-success py-2"
                                                        <?php echo e($article->verifications->where('user_id', Auth::id())->where('type', 'public')->count() ? 'disabled' : ''); ?>>
                                                        <i class="fas fa-bullhorn me-2"></i>Verifikasi Publik
                                                    </button>
                                                </form>
                                            </li>
                                        <?php endif; ?>
                                        
                                        <li><hr class="dropdown-divider"></li>
                                        <li>
                                            <a class="dropdown-item py-2" href="<?php echo e(route('kms.public.show', $article->slug)); ?>" target="_blank">
                                                <i class="fas fa-eye me-2 text-info"></i>Lihat Artikel
                                            </a>
                                        </li>
                                        <li>
                                            <a class="dropdown-item py-2" href="<?php echo e(route('kms.admin.edit', $article->id)); ?>">
                                                <i class="fas fa-edit me-2 text-primary"></i>Edit
                                            </a>
                                        </li>
                                        <li>
                                            <form action="<?php echo e(route('kms.admin.destroy', $article->id)); ?>" method="POST" class="form-delete-article">
                                                <?php echo csrf_field(); ?>
                                                <?php echo method_field('DELETE'); ?>
                                                <button type="button" class="dropdown-item text-danger py-2 btn-delete-confirm">
                                                    <i class="fas fa-trash me-2"></i>Hapus
                                                </button>
                                            </form>
                                        </li>
                                    </ul>
                                </div>
                            </td>
                        </tr>
                        <?php endforeach; $__env->popLoop(); $loop = $__env->getLastLoop(); if ($__empty_1): ?>
                        <tr>
                            <td colspan="8" class="text-center py-5 text-muted italic">
                                Belum ada artikel penugasan KMS.
                            </td>
                        </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
            <div class="p-4 border-top">
                <?php echo e($articles->links()); ?>

            </div>
        </div>
    </div>

<?php $__env->startPush('modals'); ?>
    
    <div class="modal fade" id="modalVerifyKms" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content border-0 shadow-lg rounded-4">
                <div class="modal-header border-0 p-4 pb-0">
                    <h5 class="modal-title fw-bold">Verifikasi Artikel KMS</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <form id="formVerifyKms" action="" method="POST">
                    <?php echo csrf_field(); ?>
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
<?php $__env->stopPush(); ?>
</div>
<?php $__env->stopSection(); ?>

<?php $__env->startPush('styles'); ?>
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
<?php $__env->stopPush(); ?>

<?php $__env->startPush('scripts'); ?>
<script>
    $(document).ready(function() {
        $('.btn-open-verify').on('click', function() {
            const id = $(this).data('id');
            const title = $(this).data('title');
            const url = "<?php echo e(route('kms.admin.verify', ':id')); ?>".replace(':id', id);
            
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
<?php $__env->stopPush(); ?>

<?php echo $__env->make('layouts.app', array_diff_key(get_defined_vars(), ['__data' => 1, '__path' => 1]))->render(); ?><?php /**PATH /var/www/resources/views/kms/admin/index.blade.php ENDPATH**/ ?>