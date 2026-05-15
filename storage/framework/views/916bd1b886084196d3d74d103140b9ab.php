<?php $__env->startSection('content'); ?>
<div class="container-fluid px-4 py-4">
    <div class="mb-4">
        <a href="<?php echo e(route('kms.admin.index')); ?>" class="btn btn-outline-secondary rounded-pill px-4 shadow-sm fw-bold">
            <i class="fas fa-arrow-left me-2"></i>Kembali
        </a>
    </div>

    <div class="card border-0 shadow-sm rounded-4">
        <div class="card-body p-4 p-md-5">
            <h2 class="fw-bold text-dark mb-4">Edit Artikel KMS</h2>
            
            <form action="<?php echo e(route('kms.admin.update', $article->id)); ?>" method="POST">
                <?php echo csrf_field(); ?>
                <?php echo method_field('PUT'); ?>
                
                <div class="row g-4">
                    <div class="col-md-8">
                        <div class="mb-4">
                            <label class="form-label fw-bold">Judul Artikel</label>
                            <input type="text" name="title" class="form-control rounded-3 p-3" value="<?php echo e(old('title', $article->title)); ?>" required>
                        </div>
                        
                        <div class="mb-4">
                            <label class="form-label fw-bold">Konten / Pembahasan</label>
                            <textarea name="content" id="editor" rows="15" class="form-control rounded-3 p-3" required><?php echo e(old('content', $article->content)); ?></textarea>
                        </div>

                        <div class="mb-4">
                            <label class="form-label fw-bold">Tag (Pisahkan dengan koma)</label>
                            <input type="text" name="tags" class="form-control rounded-3 p-3" value="<?php echo e(old('tags', $article->tags)); ?>" placeholder="Contoh: aplikasi, rekrutmen, error">
                            <small class="text-muted">Masukkan kata kunci untuk memudahkan pencarian.</small>
                        </div>
                    </div>
                    
                    <div class="col-md-4">
                        <div class="bg-light rounded-4 p-4 sticky-top" style="top: 2rem;">
                            <div class="mb-4">
                                <label class="form-label fw-bold">Kategori</label>
                                <select name="category_id" class="form-select rounded-3 p-3">
                                    <?php $__currentLoopData = $categories; $__env->addLoop($__currentLoopData); foreach($__currentLoopData as $category): $__env->incrementLoopIndices(); $loop = $__env->getLastLoop(); ?>
                                        <option value="<?php echo e($category->id); ?>" <?php echo e($article->category_id == $category->id ? 'selected' : ''); ?>><?php echo e($category->name); ?></option>
                                    <?php endforeach; $__env->popLoop(); $loop = $__env->getLastLoop(); ?>
                                </select>
                            </div>
                            
                            <div class="mb-4">
                                <label class="form-label fw-bold">Status Publikasi</label>
                                <div class="form-check form-switch p-3 bg-white rounded-3 border">
                                    <input class="form-check-input ms-0 me-3" type="checkbox" name="is_published" value="1" <?php echo e($article->is_published ? 'checked' : ''); ?>>
                                    <label class="form-check-label fw-bold">Publikasikan</label>
                                </div>
                                <small class="text-muted d-block mt-2">Jika diaktifkan, artikel dapat dilihat oleh masyarakat umum.</small>
                            </div>
                            
                            <hr class="my-4">
                            
                            <button type="submit" class="btn btn-primary w-100 py-3 rounded-pill fw-bold text-uppercase tracking-widest shadow-sm">
                                Simpan Perubahan
                            </button>
                        </div>
                    </div>
                </div>
            </form>
        </div>
    </div>
</div>
<?php $__env->stopSection(); ?>

<?php $__env->startPush('scripts'); ?>
<script src="https://cdn.ckeditor.com/ckeditor5/41.1.0/classic/ckeditor.js"></script>
<script>
    ClassicEditor
        .create(document.querySelector('#editor'), {
            toolbar: ['heading', '|', 'bold', 'italic', 'link', 'bulletedList', 'numberedList', 'blockQuote', 'undo', 'redo'],
        })
        .catch(error => {
            console.error(error);
        });
</script>
<?php $__env->stopPush(); ?>

<?php echo $__env->make('layouts.app', array_diff_key(get_defined_vars(), ['__data' => 1, '__path' => 1]))->render(); ?><?php /**PATH /var/www/resources/views/kms/admin/edit.blade.php ENDPATH**/ ?>