<?php $__env->startSection('content'); ?>
<div class="container-fluid px-4 py-4">
    <div class="mb-4">
        <a href="<?php echo e(route('ticket.admin.index')); ?>" class="btn btn-outline-secondary rounded-pill px-4 shadow-sm fw-bold">
            <i class="fas fa-arrow-left me-2"></i>Kembali
        </a>
    </div>
    <div class="row g-4">
        
        <div class="col-lg-8">
            <div class="card border-0 shadow-sm rounded-4 mb-4">
                <div class="card-body p-4 p-md-5">
                    <div class="d-flex justify-content-between align-items-start mb-4">
                        <div>
                            <span class="badge bg-primary bg-opacity-10 text-primary rounded-pill mb-2">#<?php echo e($ticket->tracking_id); ?></span>
                            <h2 class="fw-bold mb-1 text-dark"><?php echo e($ticket->subject); ?></h2>
                            <p class="text-muted small mb-0">
                                Dilaporkan oleh <strong><?php echo e($ticket->reporter_name); ?></strong> (<?php echo e($ticket->reporter_organization); ?>) 
                                pada <?php echo e($ticket->created_at->format('d M Y, H:i')); ?>

                            </p>
                            <div class="mt-2 d-flex gap-3 flex-wrap">
                                <span class="small text-muted"><i class="fas fa-phone me-1"></i> <?php echo e($ticket->reporter_phone); ?></span>
                                <?php if($ticket->reporter_email): ?>
                                    <span class="small text-muted"><i class="fas fa-envelope me-1"></i> <?php echo e($ticket->reporter_email); ?></span>
                                <?php endif; ?>
                                <span class="badge bg-light text-dark border rounded-pill small fw-bold">
                                    <i class="fas fa-bell me-1 text-primary"></i> Notif: <?php echo e(ucfirst($ticket->notification_method)); ?>

                                </span>
                            </div>
                        </div>
                        <?php
                            $statusClass = [
                                'open' => 'warning',
                                'assigned' => 'info',
                                'onprogress' => 'primary',
                                'check wa' => 'success',
                                'closed' => 'secondary'
                            ][$ticket->status] ?? 'secondary';
                        ?>
                        <div class="d-flex align-items-center gap-2">
                            <span class="badge bg-<?php echo e($statusClass); ?> rounded-pill px-4 py-2 text-uppercase fw-bold shadow-sm">
                                <?php echo e($ticket->status); ?>

                            </span>
                            <?php if($ticket->status === 'check wa'): ?>
                                <span class="badge bg-<?php echo e($ticket->wa_status === 'Sent' ? 'success' : 'light text-dark border'); ?> rounded-pill px-3 py-2 small shadow-sm">
                                    <i class="fab fa-whatsapp me-1 <?php echo e($ticket->wa_status === 'Sent' ? '' : 'text-success'); ?>"></i>
                                    <?php echo e($ticket->wa_status === 'Sent' ? 'USER MEMBALAS' : 'PENDING WA'); ?>

                                </span>
                            <?php endif; ?>
                        </div>
                    </div>

                    
                    <?php if($ticket->status === 'check wa'): ?>
                        <?php
                            $isPj = (is_array($ticket->category->pj_ids) && in_array(Auth::id(), $ticket->category->pj_ids)) || (is_array($ticket->assigned_to_ids) && in_array(Auth::id(), $ticket->assigned_to_ids));
                        ?>
                        
                        <?php if($ticket->wa_status === 'Pending'): ?>
                            <?php if($isPj): ?>
                            <div class="alert alert-primary border-0 rounded-4 p-4 mb-4 shadow-sm animate__animated animate__pulse animate__infinite">
                                <div class="d-flex align-items-center mb-3">
                                    <div class="bg-primary text-white rounded-circle p-2 me-3">
                                        <i class="fab fa-whatsapp fs-4"></i>
                                    </div>
                                    <h5 class="fw-bold mb-0">Koordinasi WhatsApp</h5>
                                </div>
                                <p class="mb-4">Apakah user sudah merespons koordinasi melalui WhatsApp?</p>
                                <div class="d-flex gap-2">
                                    <form action="<?php echo e(route('ticket.admin.update', $ticket->id)); ?>" method="POST">
                                        <?php echo csrf_field(); ?>
                                        <?php echo method_field('PATCH'); ?>
                                        <input type="hidden" name="status" value="check wa">
                                        <input type="hidden" name="wa_status" value="Sent">
                                        <button type="submit" class="btn btn-primary rounded-pill px-4">
                                            <i class="fas fa-check me-2"></i> Sudah Dibalas
                                        </button>
                                    </form>
                                    <form action="<?php echo e(route('ticket.admin.update', $ticket->id)); ?>" method="POST">
                                        <?php echo csrf_field(); ?>
                                        <?php echo method_field('PATCH'); ?>
                                        <input type="hidden" name="status" value="onprogress">
                                        <input type="hidden" name="wa_status" value="None">
                                        <button type="submit" class="btn btn-outline-secondary rounded-pill px-4">
                                            Kembali ke Progress
                                        </button>
                                    </form>
                                </div>
                            </div>
                            <?php else: ?>
                            <div class="alert alert-light border rounded-4 p-4 mb-4">
                                <div class="d-flex align-items-center text-muted">
                                    <div class="spinner-grow spinner-grow-sm text-primary me-3" role="status"></div>
                                    <span>Menunggu PJ mengonfirmasi status WhatsApp...</span>
                                </div>
                            </div>
                            <?php endif; ?>
                        <?php elseif($ticket->wa_status === 'Sent'): ?>
                            <div class="alert alert-success border-0 rounded-4 p-4 mb-4 shadow-sm">
                                <div class="d-flex align-items-center">
                                    <div class="bg-success text-white rounded-circle p-2 me-3">
                                        <i class="fab fa-whatsapp fs-4"></i>
                                    </div>
                                    <div>
                                        <h6 class="fw-bold mb-1">Status: WhatsApp Terhubung</h6>
                                        <p class="mb-0 small opacity-75">User telah merespons via WhatsApp. Selesaikan tiket jika kendala sudah teratasi.</p>
                                    </div>
                                </div>
                            </div>
                        <?php endif; ?>
                    <?php endif; ?>

                    <div class="bg-light rounded-4 p-4 mb-4">
                        <h6 class="fw-bold text-primary small text-uppercase tracking-widest mb-3">Deskripsi Masalah</h6>
                        <p class="text-dark mb-0" style="white-space: pre-line;"><?php echo e($ticket->description); ?></p>
                    </div>

                    <?php if($ticket->attachment): ?>
                    <div class="mb-4">
                        <h6 class="fw-bold small text-uppercase mb-2">Lampiran</h6>
                        <a href="<?php echo e(asset('storage/' . $ticket->attachment)); ?>" target="_blank" class="btn btn-outline-dark btn-sm rounded-4 px-3">
                            <i class="fas fa-paperclip me-2"></i> Lihat Lampiran
                        </a>
                    </div>
                    <?php endif; ?>

                    <hr class="my-5 opacity-10">

                    
                    <h5 class="fw-bold mb-4">Percakapan</h5>
                    <div class="d-flex flex-column gap-4 mb-5">
                        <?php $__empty_1 = true; $__currentLoopData = $ticket->replies; $__env->addLoop($__currentLoopData); foreach($__currentLoopData as $reply): $__env->incrementLoopIndices(); $loop = $__env->getLastLoop(); $__empty_1 = false; ?>
                        <div class="d-flex <?php echo e($reply->is_admin ? 'justify-content-end' : ''); ?>">
                            <div class="card border-0 rounded-4 <?php echo e($reply->is_admin ? 'bg-primary text-white' : 'bg-light'); ?> shadow-sm" style="max-width: 80%;">
                                <div class="card-body p-3 px-4">
                                    <div class="d-flex align-items-center mb-2">
                                        <small class="fw-bold me-2"><?php echo e($reply->user ? $reply->user->nama_lengkap : 'Sistem'); ?></small>
                                        <small class="opacity-75" style="font-size: 0.7rem;"><?php echo e($reply->created_at->diffForHumans()); ?></small>
                                    </div>
                                    <p class="mb-0"><?php echo e($reply->message); ?></p>
                                </div>
                            </div>
                        </div>
                        <?php endforeach; $__env->popLoop(); $loop = $__env->getLastLoop(); if ($__empty_1): ?>
                        <div class="text-center py-4 text-muted">
                            <p class="small italic">Belum ada percakapan.</p>
                        </div>
                        <?php endif; ?>
                    </div>

                    
                    <?php if($ticket->status !== 'closed' && Auth::user()->can('can-manage-ticket', $ticket)): ?>
                    <form action="<?php echo e(route('ticket.admin.reply', $ticket->id)); ?>" method="POST" class="mt-4">
                        <?php echo csrf_field(); ?>
                        <div class="card border-0 bg-light rounded-4">
                            <div class="card-body p-3">
                                <textarea name="message" rows="3" class="form-control bg-transparent border-0 shadow-none" placeholder="Tulis balasan di sini..." required></textarea>
                                <div class="d-flex justify-content-between align-items-center mt-2">
                                    <button type="submit" class="btn btn-primary rounded-pill px-4 btn-sm">
                                        <i class="fas fa-paper-plane me-2"></i> Kirim Balasan
                                    </button>
                                </div>
                            </div>
                        </div>
                    </form>
                    <?php endif; ?>
                </div>
            </div>

            
            <div class="card border-0 shadow-sm rounded-4">
                <div class="card-body p-4 p-md-5">
                    <h5 class="fw-bold mb-4">Riwayat Aktivitas</h5>
                    <div class="timeline ps-4 border-start">
                        <?php $__currentLoopData = $ticket->activities; $__env->addLoop($__currentLoopData); foreach($__currentLoopData as $activity): $__env->incrementLoopIndices(); $loop = $__env->getLastLoop(); ?>
                        <div class="timeline-item mb-4 position-relative">
                            <div class="timeline-dot bg-secondary"></div>
                            <div class="small text-muted mb-1"><?php echo e($activity->created_at->format('d M Y, H:i')); ?></div>
                            <div class="fw-bold text-dark small"><?php echo e($activity->message); ?></div>
                        </div>
                        <?php endforeach; $__env->popLoop(); $loop = $__env->getLastLoop(); ?>
                    </div>
                </div>
            </div>
        </div>

        
        <?php if (app(\Illuminate\Contracts\Auth\Access\Gate::class)->check('can-manage-ticket', $ticket)): ?>
        <div class="col-lg-4">
            <div class="card border-0 shadow-sm rounded-4 mb-4 sticky-top" style="top: 2rem;">
                <div class="card-body p-4">
                    <h5 class="fw-bold mb-4">Manajemen Tiket</h5>
                    
                    <form action="<?php echo e(route('ticket.admin.update', $ticket->id)); ?>" method="POST">
                        <?php echo csrf_field(); ?>
                        <?php echo method_field('PATCH'); ?>
                        
                        <div class="mb-4">
                            <?php
                                $canChangeCategory = Auth::user()->role === 'Admin' || Auth::user()->username === 'ketua.tim';
                            ?>
                            <label class="form-label small fw-bold text-muted text-uppercase">Kategori (Admin/Katim Only)</label>
                            <select name="category_id" class="form-select rounded-4 border-light bg-light p-3" <?php echo e(!$canChangeCategory ? 'disabled' : ''); ?>>
                                <?php $__currentLoopData = \App\Models\TicketCategory::all(); $__env->addLoop($__currentLoopData); foreach($__currentLoopData as $cat): $__env->incrementLoopIndices(); $loop = $__env->getLastLoop(); ?>
                                    <option value="<?php echo e($cat->id); ?>" <?php echo e($ticket->category_id == $cat->id ? 'selected' : ''); ?>><?php echo e($cat->name); ?></option>
                                <?php endforeach; $__env->popLoop(); $loop = $__env->getLastLoop(); ?>
                            </select>
                            <?php if($canChangeCategory): ?>
                                <small class="text-danger mt-1 d-block" style="font-size: 0.6rem;">* Mengubah kategori akan mereset Kode Tiket.</small>
                            <?php endif; ?>
                        </div>

                        <div class="mb-4">
                            <label class="form-label small fw-bold text-muted text-uppercase">Update Status</label>
                            <select name="status" class="form-select rounded-4 border-light bg-light p-3">
                                <option value="open" <?php echo e($ticket->status == 'open' ? 'selected' : ''); ?>>OPEN</option>
                                <option value="assigned" <?php echo e($ticket->status == 'assigned' ? 'selected' : ''); ?>>ASSIGNED</option>
                                <option value="onprogress" <?php echo e($ticket->status == 'onprogress' ? 'selected' : ''); ?>>ON PROGRESS</option>
                                <option value="check wa" <?php echo e($ticket->status == 'check wa' ? 'selected' : ''); ?>>CHECK WA</option>
                                <option value="closed" <?php echo e($ticket->status == 'closed' ? 'selected' : ''); ?>>CLOSED</option>
                            </select>
                        </div>

                        
                        <?php if($ticket->status === 'check wa'): ?>
                        <div class="mb-4">
                            <label class="form-label small fw-bold text-muted text-uppercase">Sub-Status WhatsApp</label>
                            <select name="wa_status" class="form-select rounded-4 border-light bg-light p-3">
                                <option value="Pending" <?php echo e($ticket->wa_status == 'Pending' ? 'selected' : ''); ?>>PENDING (Menunggu User)</option>
                                <option value="Sent" <?php echo e($ticket->wa_status == 'Sent' ? 'selected' : ''); ?>>SENT (User Membalas)</option>
                            </select>
                        </div>
                        <?php endif; ?>

                        <div class="mb-4">
                            <label class="form-label small fw-bold text-muted text-uppercase">Tugaskan Ke (PJ Kategori: <?php echo e($ticket->category->name); ?>)</label>
                            <select id="select-petugas" name="assigned_to_ids[]" class="form-control" multiple="multiple" style="width: 100%">
                                <?php $__currentLoopData = $admins; $__env->addLoop($__currentLoopData); foreach($__currentLoopData as $admin): $__env->incrementLoopIndices(); $loop = $__env->getLastLoop(); ?>
                                    <option value="<?php echo e($admin->id); ?>" <?php echo e(in_array($admin->id, $ticket->assigned_to_ids ?? []) ? 'selected' : ''); ?>>
                                        <?php echo e($admin->nama_lengkap); ?>

                                    </option>
                                <?php endforeach; $__env->popLoop(); $loop = $__env->getLastLoop(); ?>
                            </select>
                            <small class="text-muted mt-1 d-block">Pilih satu atau lebih petugas pelaksana.</small>
                        </div>

                        <div class="mb-4">
                            <label class="form-label small fw-bold text-muted text-uppercase">Solusi / Catatan Internal</label>
                            <textarea name="solution" rows="4" class="form-control rounded-4 border-light bg-light p-3" placeholder="Tuliskan solusi jika tiket ditutup..."><?php echo e($ticket->solution); ?></textarea>
                        </div>

                        <button type="submit" class="btn btn-dark w-100 py-3 rounded-pill fw-bold text-uppercase tracking-widest shadow-sm">
                            Simpan Perubahan
                        </button>
                    </form>

                    <?php if($ticket->status === 'onprogress'): ?>
                    <hr class="my-4">
                    <div class="text-center">
                        <p class="small text-muted mb-3">Lanjut koordinasi via WhatsApp dengan user?</p>
                        <form action="<?php echo e(route('ticket.admin.update', $ticket->id)); ?>" method="POST">
                            <?php echo csrf_field(); ?>
                            <?php echo method_field('PATCH'); ?>
                            <input type="hidden" name="status" value="check wa">
                            <input type="hidden" name="wa_status" value="Pending">
                            <button type="submit" class="btn btn-outline-success w-100 py-3 rounded-pill fw-bold text-uppercase shadow-sm">
                                <i class="fab fa-whatsapp me-2"></i> Lanjut Ke WA
                            </button>
                        </form>
                    </div>
                    <?php endif; ?>

                    <?php if($ticket->status === 'closed' && !$ticket->pushed_to_kms): ?>
                    <hr class="my-4">
                    <div class="text-center">
                        <p class="small text-muted mb-3">Tiket selesai. Bagikan solusi ini ke Knowledge Management System (KMS)?</p>
                        <form action="<?php echo e(route('ticket.admin.push', $ticket->id)); ?>" method="POST">
                            <?php echo csrf_field(); ?>
                            <button type="submit" class="btn btn-success w-100 py-3 rounded-pill fw-bold text-uppercase shadow-sm">
                                <i class="fas fa-share-square me-2"></i> Push ke KMS
                            </button>
                        </form>
                    </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
        <?php else: ?>
        <div class="col-lg-4">
            
            <?php if($ticket->status === 'closed' && !$ticket->pushed_to_kms): ?>
            <div class="card border-0 shadow-sm rounded-4 mb-4 p-4 text-center">
                <div class="bg-success bg-opacity-10 text-success rounded-circle p-3 d-inline-block mx-auto mb-3">
                    <i class="fas fa-lightbulb fa-2x"></i>
                </div>
                <h6 class="fw-bold mb-2">Push ke KMS</h6>
                <p class="small text-muted mb-4">Tiket ini sudah selesai. Semua pegawai dapat membantu membagikan solusi ini ke sistem KMS.</p>
                <form action="<?php echo e(route('ticket.admin.push', $ticket->id)); ?>" method="POST">
                    <?php echo csrf_field(); ?>
                    <button type="submit" class="btn btn-success w-100 py-3 rounded-pill fw-bold text-uppercase shadow-sm">
                        <i class="fas fa-share-square me-2"></i> Bagikan Solusi
                    </button>
                </form>
            </div>
            <?php endif; ?>

            <div class="card border-0 shadow-sm rounded-4 mb-4 text-center p-4">
                <div class="bg-primary bg-opacity-10 text-primary rounded-circle p-3 d-inline-block mx-auto mb-3">
                    <i class="fas fa-info-circle fa-2x"></i>
                </div>
                <h6 class="fw-bold mb-2">Info Penanganan</h6>
                <p class="small text-muted mb-0">Tiket ini sedang ditangani oleh Tim IT BPS Tuban. Hanya Admin, Ketua Tim, atau PJ yang ditunjuk yang dapat mengubah status tiket.</p>
            </div>
        </div>
        <?php endif; ?>
    </div>
</div>

<style>
    .timeline { border-color: #f1f5f9 !important; }
    .timeline-dot {
        position: absolute;
        left: -32px;
        top: 5px;
        width: 13px;
        height: 13px;
        border-radius: 50%;
        border: 2px solid white;
        box-shadow: 0 0 0 1px #e2e8f0;
    }
</style>
<?php $__env->startPush('scripts'); ?>
<script>
    $(document).ready(function() {
        $('#select-petugas').select2({
            placeholder: 'Pilih Petugas...',
            allowClear: true
        });
    });
</script>
<?php $__env->stopPush(); ?>
<?php $__env->stopSection(); ?>

<?php echo $__env->make('layouts.app', array_diff_key(get_defined_vars(), ['__data' => 1, '__path' => 1]))->render(); ?><?php /**PATH /var/www/resources/views/ticket/admin/show.blade.php ENDPATH**/ ?>