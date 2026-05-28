<?php $__env->startSection('content'); ?>
<div class="container">
    <nav aria-label="breadcrumb" class="mb-4">
        <ol class="breadcrumb">
            <li class="breadcrumb-item"><a href="<?php echo e(route('kms.public.index')); ?>" class="text-decoration-none">Knowledge Base</a></li>
            <li class="breadcrumb-item active" aria-current="page"><?php echo e($article->category->name); ?></li>
        </ol>
    </nav>

    <div class="row justify-content-center">
        <div class="col-lg-8">
            <div class="card border-0 shadow-sm overflow-hidden">
                <div class="card-body p-lg-5 p-4">
                    <div class="mb-3">
                        <span class="badge bg-primary-subtle text-primary rounded-pill px-3"><?php echo e($article->category->name); ?></span>
                    </div>
                    <h1 class="fw-bold mb-4"><?php echo e($article->title); ?></h1>
                    
                    <div class="d-flex align-items-center mb-5 text-muted small border-bottom pb-4">
                        <div class="d-flex align-items-center me-4">
                            <i class="far fa-user me-2"></i> <?php echo e($article->author->nama_lengkap ?? 'Tim Humas BPS'); ?>

                        </div>
                        <div class="d-flex align-items-center me-4">
                            <i class="far fa-calendar me-2"></i> <?php echo e($article->created_at->format('d M Y')); ?>

                        </div>
                        <div class="d-flex align-items-center">
                            <i class="far fa-eye me-2"></i> <?php echo e($article->view_count); ?>x dilihat
                        </div>
                    </div>

                    <div class="article-content lh-lg">
                        <?php echo $article->content; ?>

                    </div>

                    <div class="mt-5 pt-5 border-top">
                        <?php
                            $userFeedback = session('kms_article_feedback_' . $article->id);
                        ?>
                        <h6 class="fw-bold mb-3" id="feedback-title">
                            <?php echo e($userFeedback ? 'Terima kasih atas masukan Anda!' : 'Apakah artikel ini membantu?'); ?>

                        </h6>
                        <div class="d-flex gap-2">
                            <button id="btn-helpful" class="btn <?php echo e($userFeedback === 'helpful' ? 'btn-primary' : 'btn-outline-primary'); ?> rounded-pill px-4" data-type="helpful" <?php echo e($userFeedback ? 'disabled' : ''); ?>>
                                <i class="far fa-thumbs-up me-2"></i> Ya, sangat membantu (<span id="helpful-count"><?php echo e($article->helpful_count ?? 0); ?></span>)
                            </button>
                            <button id="btn-not-helpful" class="btn <?php echo e($userFeedback === 'not_helpful' ? 'btn-secondary' : 'btn-outline-secondary'); ?> rounded-pill px-4" data-type="not_helpful" <?php echo e($userFeedback ? 'disabled' : ''); ?>>
                                <i class="far fa-thumbs-down me-2"></i> Belum membantu (<span id="not-helpful-count"><?php echo e($article->not_helpful_count ?? 0); ?></span>)
                            </button>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="text-center mt-5">
                <a href="<?php echo e(route('kms.public.index')); ?>" class="btn btn-link text-decoration-none">
                    <i class="fas fa-arrow-left me-2"></i> Kembali ke daftar artikel
                </a>
            </div>
        </div>
    </div>
</div>

<style>
    .article-content img { max-width: 100%; height: auto; border-radius: 15px; margin: 1.5rem 0; }
    .bg-primary-subtle { background-color: #eef6ff; }
</style>
<?php $__env->stopSection(); ?>

<?php $__env->startSection('scripts'); ?>
<script>
document.addEventListener('DOMContentLoaded', function () {
    const helpfulBtn = document.getElementById('btn-helpful');
    const notHelpfulBtn = document.getElementById('btn-not-helpful');
    const feedbackTitle = document.getElementById('feedback-title');

    function sendFeedback(type) {
        if (!helpfulBtn || !notHelpfulBtn) return;
        
        helpfulBtn.disabled = true;
        notHelpfulBtn.disabled = true;

        fetch("<?php echo e(route('kms.public.feedback', $article->slug)); ?>", {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-TOKEN': '<?php echo e(csrf_token()); ?>'
            },
            body: JSON.stringify({ type: type })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                if (type === 'helpful') {
                    helpfulBtn.classList.remove('btn-outline-primary');
                    helpfulBtn.classList.add('btn-primary');
                } else {
                    notHelpfulBtn.classList.remove('btn-outline-secondary');
                    notHelpfulBtn.classList.add('btn-secondary');
                }
                
                // Update counts in DOM
                if (data.helpful_count !== undefined) {
                    document.getElementById('helpful-count').textContent = data.helpful_count;
                }
                if (data.not_helpful_count !== undefined) {
                    document.getElementById('not-helpful-count').textContent = data.not_helpful_count;
                }
                
                feedbackTitle.textContent = 'Terima kasih atas masukan Anda!';

                Swal.fire({
                    toast: true,
                    position: 'top-end',
                    icon: 'success',
                    title: data.message,
                    showConfirmButton: false,
                    timer: 3000,
                    timerProgressBar: true
                });
            } else {
                if (data.message.includes('sudah')) {
                    feedbackTitle.textContent = 'Terima kasih atas masukan Anda!';
                } else {
                    helpfulBtn.disabled = false;
                    notHelpfulBtn.disabled = false;
                }
                
                Swal.fire({
                    toast: true,
                    position: 'top-end',
                    icon: 'warning',
                    title: data.message,
                    showConfirmButton: false,
                    timer: 3000,
                    timerProgressBar: true
                });
            }
        })
        .catch(error => {
            console.error('Error submitting feedback:', error);
            helpfulBtn.disabled = false;
            notHelpfulBtn.disabled = false;
            
            Swal.fire({
                toast: true,
                position: 'top-end',
                icon: 'error',
                title: 'Terjadi kesalahan. Silakan coba lagi.',
                showConfirmButton: false,
                timer: 3000
            });
        });
    }

    if (helpfulBtn && !helpfulBtn.disabled) {
        helpfulBtn.addEventListener('click', function () {
            sendFeedback('helpful');
        });
    }

    if (notHelpfulBtn && !notHelpfulBtn.disabled) {
        notHelpfulBtn.addEventListener('click', function () {
            sendFeedback('not_helpful');
        });
    }
});
</script>
<?php $__env->stopSection(); ?>

<?php echo $__env->make('layouts.public', array_diff_key(get_defined_vars(), ['__data' => 1, '__path' => 1]))->render(); ?><?php /**PATH /var/www/resources/views/kms/public/show.blade.php ENDPATH**/ ?>