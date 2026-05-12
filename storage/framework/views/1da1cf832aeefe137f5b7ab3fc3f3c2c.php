<?php $__env->startSection('content'); ?>
<div class="container">
    <div class="row justify-content-center mb-5">
        <div class="col-md-8 text-center">
            <h2 class="fw-bold text-primary mb-3">Knowledge Base</h2>
            <p class="text-muted">Temukan jawaban dan panduan seputar layanan BPS Kabupaten Tuban</p>
            
            <form action="<?php echo e(route('kms.public.index')); ?>" method="GET" class="mt-4">
                <div class="input-group input-group-lg shadow-sm rounded-pill overflow-hidden border">
                    <span class="input-group-text bg-white border-0 ps-4">
                        <i class="fas fa-search text-muted"></i>
                    </span>
                    <input type="text" name="q" class="form-control border-0 px-3" placeholder="Cari panduan atau artikel..." value="<?php echo e(request('q')); ?>">
                    <button class="btn btn-primary px-4 fw-bold" type="submit">Cari</button>
                </div>
            </form>
        </div>
    </div>

    <div class="row g-4">
        
        <div class="col-lg-3">
            <div class="card border-0 shadow-sm p-3">
                <h6 class="fw-bold mb-3 px-2">Kategori</h6>
                <div class="list-group list-group-flush">
                    <a href="<?php echo e(route('kms.public.index')); ?>" class="list-group-item list-group-item-action border-0 rounded-3 mb-1 <?php echo e(!request('category') ? 'active' : ''); ?>">
                        Semua Artikel
                    </a>
                    <?php $__currentLoopData = $categories; $__env->addLoop($__currentLoopData); foreach($__currentLoopData as $cat): $__env->incrementLoopIndices(); $loop = $__env->getLastLoop(); ?>
                    <a href="<?php echo e(route('kms.public.index', ['category' => $cat->slug])); ?>" class="list-group-item list-group-item-action border-0 rounded-3 mb-1 d-flex justify-content-between align-items-center">
                        <?php echo e($cat->name); ?>

                        <span class="badge bg-light text-muted rounded-pill"><?php echo e($cat->articles_count); ?></span>
                    </a>
                    <?php endforeach; $__env->popLoop(); $loop = $__env->getLastLoop(); ?>
                </div>
            </div>
        </div>

        
        <div class="col-lg-9">
            <div class="row g-4">
                <?php $__empty_1 = true; $__currentLoopData = $articles; $__env->addLoop($__currentLoopData); foreach($__currentLoopData as $article): $__env->incrementLoopIndices(); $loop = $__env->getLastLoop(); $__empty_1 = false; ?>
                <div class="col-md-6">
                    <div class="card h-100 border-0 shadow-sm hover-up">
                        <div class="card-body p-4">
                            <div class="mb-2">
                                <span class="badge bg-primary-subtle text-primary rounded-pill px-3"><?php echo e($article->category->name); ?></span>
                            </div>
                            <h5 class="fw-bold mb-3">
                                <a href="<?php echo e(route('kms.public.show', $article->slug)); ?>" class="text-decoration-none text-dark">
                                    <?php echo e($article->title); ?>

                                </a>
                            </h5>
                            <p class="text-muted small mb-4">
                                <?php echo e(Str::limit(strip_tags($article->content), 120)); ?>

                            </p>
                            <div class="d-flex align-items-center justify-content-between mt-auto">
                                <small class="text-muted"><i class="far fa-calendar me-1"></i> <?php echo e($article->created_at->format('d M Y')); ?></small>
                                <a href="<?php echo e(route('kms.public.show', $article->slug)); ?>" class="btn btn-link text-primary p-0 fw-bold text-decoration-none">
                                    Baca Selengkapnya <i class="fas fa-chevron-right ms-1 small"></i>
                                </a>
                            </div>
                        </div>
                    </div>
                </div>
                <?php endforeach; $__env->popLoop(); $loop = $__env->getLastLoop(); if ($__empty_1): ?>
                <div class="col-12 text-center py-5">
                    <img src="https://illustrations.popsy.co/amber/waiting-for-customer.svg" alt="Empty" style="height: 200px;" class="mb-4">
                    <h5 class="text-muted">Belum ada artikel yang tersedia.</h5>
                </div>
                <?php endif; ?>
            </div>

            <div class="mt-5">
                <?php echo e($articles->links()); ?>

            </div>
        </div>
    </div>
</div>

<style>
    .hover-up { transition: all 0.3s; }
    .hover-up:hover { transform: translateY(-5px); box-shadow: 0 15px 30px rgba(0,0,0,0.08) !important; }
    .bg-primary-subtle { background-color: #eef6ff; }
</style>
<?php $__env->stopSection(); ?>

<?php echo $__env->make('layouts.public', array_diff_key(get_defined_vars(), ['__data' => 1, '__path' => 1]))->render(); ?><?php /**PATH /var/www/resources/views/kms/public/index.blade.php ENDPATH**/ ?>