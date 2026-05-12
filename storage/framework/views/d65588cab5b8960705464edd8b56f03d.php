<?php $__env->startSection('content'); ?>
<div class="container">
    <div class="row justify-content-center">
        <div class="col-lg-8">
            
            <div class="card border-0 shadow-sm mb-4 overflow-hidden">
                <div class="card-body p-lg-5 p-4">
                    <div class="d-flex justify-content-between align-items-start mb-4">
                        <div>
                            <small class="text-muted text-uppercase fw-bold">Status Tiket #<?php echo e($ticket->tracking_id); ?></small>
                            <h2 class="fw-bold mt-1"><?php echo e($ticket->subject); ?></h2>
                        </div>
                        <span class="badge rounded-pill px-4 py-2 
                            <?php echo e($ticket->status == 'open' ? 'bg-warning text-dark' : ''); ?>

                            <?php echo e($ticket->status == 'onprogress' ? 'bg-info text-dark' : ''); ?>

                            <?php echo e($ticket->status == 'confirm WA' ? 'bg-primary' : ''); ?>

                            <?php echo e($ticket->status == 'closed' ? 'bg-success' : ''); ?>">
                            <?php echo e(strtoupper($ticket->status)); ?>

                        </span>
                    </div>

                    <div class="row g-4 py-4 border-top border-bottom mb-4">
                        <div class="col-md-4">
                            <small class="text-muted d-block mb-1">Tanggal Lapor</small>
                            <span class="fw-bold"><?php echo e($ticket->created_at->format('d M Y, H:i')); ?></span>
                        </div>
                        <div class="col-md-4">
                            <small class="text-muted d-block mb-1">Kategori</small>
                            <span class="fw-bold"><?php echo e($ticket->category->name); ?></span>
                        </div>
                        <div class="col-md-4">
                            <small class="text-muted d-block mb-1">Prioritas</small>
                            <span class="badge bg-light text-dark border"><?php echo e(strtoupper($ticket->priority)); ?></span>
                        </div>
                    </div>

                    <h6 class="fw-bold mb-3 text-primary text-uppercase small tracking-widest">Deskripsi Masalah</h6>
                    <p class="text-dark mb-4" style="white-space: pre-line;"><?php echo e($ticket->description); ?></p>

                    <?php if($ticket->solution): ?>
                    <div class="alert alert-success border-0 rounded-4 p-4 mt-4 shadow-sm">
                        <h6 class="fw-bold mb-2 text-success"><i class="fas fa-check-circle me-2"></i> Solusi dari Petugas</h6>
                        <p class="mb-0"><?php echo e($ticket->solution); ?></p>
                    </div>
                    <?php endif; ?>
                </div>
            </div>

            
            <?php if($ticket->replies->count() > 0): ?>
            <div class="card border-0 shadow-sm rounded-4 mb-4">
                <div class="card-body p-lg-5 p-4">
                    <h5 class="fw-bold mb-4">Percakapan & Balasan</h5>
                    <div class="d-flex flex-column gap-3">
                        <?php $__currentLoopData = $ticket->replies; $__env->addLoop($__currentLoopData); foreach($__currentLoopData as $reply): $__env->incrementLoopIndices(); $loop = $__env->getLastLoop(); ?>
                        <div class="d-flex <?php echo e($reply->is_admin ? 'justify-content-start' : 'justify-content-end'); ?>">
                            <div class="p-3 rounded-4 <?php echo e($reply->is_admin ? 'bg-light text-dark border-start border-4 border-primary' : 'bg-primary text-white'); ?>" style="max-width: 85%;">
                                <div class="d-flex justify-content-between align-items-center mb-1">
                                    <small class="fw-bold"><?php echo e($reply->user ? $reply->user->nama_lengkap : 'Petugas'); ?></small>
                                    <small class="opacity-75 ms-3" style="font-size: 0.65rem;"><?php echo e($reply->created_at->format('d M, H:i')); ?></small>
                                </div>
                                <p class="mb-0 small"><?php echo e($reply->message); ?></p>
                            </div>
                        </div>
                        <?php endforeach; $__env->popLoop(); $loop = $__env->getLastLoop(); ?>
                    </div>
                </div>
            </div>
            <?php endif; ?>

            
            <div class="card border-0 shadow-sm rounded-4 mb-4">
                <div class="card-body p-lg-5 p-4">
                    <h5 class="fw-bold mb-4">Riwayat Aktivitas</h5>
                    <div class="timeline-container ms-3 ps-4 border-start">
                        <?php $__currentLoopData = $ticket->activities; $__env->addLoop($__currentLoopData); foreach($__currentLoopData as $activity): $__env->incrementLoopIndices(); $loop = $__env->getLastLoop(); ?>
                        <div class="timeline-item mb-4 position-relative">
                            <div class="timeline-marker"></div>
                            <div class="small text-muted mb-1"><?php echo e($activity->created_at->format('d M Y, H:i')); ?></div>
                            <div class="fw-bold text-dark small"><?php echo e($activity->message); ?></div>
                        </div>
                        <?php endforeach; $__env->popLoop(); $loop = $__env->getLastLoop(); ?>
                        
                        <div class="timeline-item position-relative">
                            <div class="timeline-marker bg-primary"></div>
                            <div class="small text-muted mb-1"><?php echo e($ticket->created_at->format('d M Y, H:i')); ?></div>
                            <div class="fw-bold text-dark small">Tiket berhasil dibuat oleh <?php echo e($ticket->reporter_name); ?></div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="text-center mt-5">
                <a href="<?php echo e(route('ticket.public.track.form')); ?>" class="btn btn-outline-primary rounded-pill px-4">
                    <i class="fas fa-arrow-left me-2"></i> Lacak Tiket Lainnya
                </a>
            </div>
        </div>
    </div>
</div>

<style>
    .timeline-container { border-color: #e2e8f0 !important; }
    .timeline-marker {
        position: absolute;
        left: -33px;
        top: 5px;
        width: 15px;
        height: 15px;
        border-radius: 50%;
        background: #cbd5e1;
        border: 3px solid white;
        box-shadow: 0 0 0 1px #e2e8f0;
    }
    .badge { font-size: 0.75rem; letter-spacing: 0.5px; }
</style>
<?php $__env->stopSection(); ?>

<?php echo $__env->make('layouts.public', array_diff_key(get_defined_vars(), ['__data' => 1, '__path' => 1]))->render(); ?><?php /**PATH /var/www/resources/views/ticket/public/show.blade.php ENDPATH**/ ?>