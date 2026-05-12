<?php $__env->startSection('content'); ?>
<div class="container-fluid px-4 pb-5">
    
    <div class="mb-4 mt-4">
        <h4 class="fw-bold text-dark mb-1">Pengaturan Profil</h4>
        <p class="text-muted small">Kelola informasi data diri dan peran akses Anda dalam sistem Harmoni.</p>
    </div>

    <div class="row justify-content-center">
        <div class="col-lg-10">
            <div class="card border-0 shadow-sm rounded-4">
                <div class="card-body p-4 p-md-5">
                    
                    
                    <form action="<?php echo e(route('profile.update')); ?>" method="POST" enctype="multipart/form-data">
                        <?php echo csrf_field(); ?>
                        <?php echo method_field('PUT'); ?>

                        <div class="row g-4">
                            
                            <div class="col-md-6 border-end pe-md-4">
                                <h6 class="fw-bold text-dark mb-4 border-bottom pb-2">
                                    <i class="fas fa-user-circle me-2 text-primary"></i>Informasi Akun
                                </h6>
                                
                                <div class="mb-3">
                                    <label class="small fw-bold mb-1">Nama Lengkap</label>
                                    <input type="text" name="nama_lengkap" class="form-control rounded-3 bg-light border-0 <?php $__errorArgs = ['nama_lengkap'];
$__bag = $errors->getBag($__errorArgs[1] ?? 'default');
if ($__bag->has($__errorArgs[0])) :
if (isset($message)) { $__messageOriginal = $message; }
$message = $__bag->first($__errorArgs[0]); ?> is-invalid <?php unset($message);
if (isset($__messageOriginal)) { $message = $__messageOriginal; }
endif;
unset($__errorArgs, $__bag); ?>" 
                                           value="<?php echo e(old('nama_lengkap', $user->nama_lengkap)); ?>" required>
                                    <?php $__errorArgs = ['nama_lengkap'];
$__bag = $errors->getBag($__errorArgs[1] ?? 'default');
if ($__bag->has($__errorArgs[0])) :
if (isset($message)) { $__messageOriginal = $message; }
$message = $__bag->first($__errorArgs[0]); ?> <div class="invalid-feedback"><?php echo e($message); ?></div> <?php unset($message);
if (isset($__messageOriginal)) { $message = $__messageOriginal; }
endif;
unset($__errorArgs, $__bag); ?>
                                </div>

                                <div class="mb-4">
                                    <label class="small fw-bold mb-1">Username</label>
                                    <input type="text" name="username" class="form-control rounded-3 bg-light border-0 <?php $__errorArgs = ['username'];
$__bag = $errors->getBag($__errorArgs[1] ?? 'default');
if ($__bag->has($__errorArgs[0])) :
if (isset($message)) { $__messageOriginal = $message; }
$message = $__bag->first($__errorArgs[0]); ?> is-invalid <?php unset($message);
if (isset($__messageOriginal)) { $message = $__messageOriginal; }
endif;
unset($__errorArgs, $__bag); ?>" 
                                           value="<?php echo e(old('username', $user->username)); ?>" required>
                                    <?php $__errorArgs = ['username'];
$__bag = $errors->getBag($__errorArgs[1] ?? 'default');
if ($__bag->has($__errorArgs[0])) :
if (isset($message)) { $__messageOriginal = $message; }
$message = $__bag->first($__errorArgs[0]); ?> <div class="invalid-feedback"><?php echo e($message); ?></div> <?php unset($message);
if (isset($__messageOriginal)) { $message = $__messageOriginal; }
endif;
unset($__errorArgs, $__bag); ?>
                                </div>

                                
                                <?php if(in_array($user->role, ['Kepala', 'Katim'])): ?>
                                <div class="mb-4 p-3 border rounded-4 bg-white shadow-xs">
                                    <label class="small fw-bold mb-2 d-block text-dark">
                                        <i class="fas fa-pen-nib me-1 text-primary"></i> Tanda Tangan Digital
                                    </label>
                                    
                                    <?php if($user->signature): ?>
                                        <div class="mb-3 p-2 border rounded bg-light text-center">
                                            <img src="<?php echo e(asset('storage/' . $user->signature)); ?>" alt="TTD Digital" style="max-height: 80px; width: auto;">
                                            <p class="text-muted mt-1 mb-0" style="font-size: 0.65rem;">Tanda tangan aktif saat ini</p>
                                        </div>
                                    <?php endif; ?>

                                    <input type="file" name="signature" class="form-control form-control-sm rounded-3 <?php $__errorArgs = ['signature'];
$__bag = $errors->getBag($__errorArgs[1] ?? 'default');
if ($__bag->has($__errorArgs[0])) :
if (isset($message)) { $__messageOriginal = $message; }
$message = $__bag->first($__errorArgs[0]); ?> is-invalid <?php unset($message);
if (isset($__messageOriginal)) { $message = $__messageOriginal; }
endif;
unset($__errorArgs, $__bag); ?>" accept="image/png">
                                    <div class="form-text text-muted" style="font-size: 0.65rem;">
                                        Format: <b>PNG Transparan</b> (Max 2MB). Digunakan untuk cetak dokumen rapat.
                                    </div>
                                    <?php $__errorArgs = ['signature'];
$__bag = $errors->getBag($__errorArgs[1] ?? 'default');
if ($__bag->has($__errorArgs[0])) :
if (isset($message)) { $__messageOriginal = $message; }
$message = $__bag->first($__errorArgs[0]); ?> <div class="invalid-feedback"><?php echo e($message); ?></div> <?php unset($message);
if (isset($__messageOriginal)) { $message = $__messageOriginal; }
endif;
unset($__errorArgs, $__bag); ?>
                                </div>
                                <?php endif; ?>

                                <h6 class="fw-bold text-dark mb-3 mt-4 border-bottom pb-2">
                                    <i class="fas fa-key me-2 text-warning"></i>Keamanan
                                </h6>
                                <div class="mb-3">
                                    <label class="small fw-bold mb-1">Password Baru</label>
                                    <input type="password" name="password" class="form-control rounded-3 bg-light border-0 <?php $__errorArgs = ['password'];
$__bag = $errors->getBag($__errorArgs[1] ?? 'default');
if ($__bag->has($__errorArgs[0])) :
if (isset($message)) { $__messageOriginal = $message; }
$message = $__bag->first($__errorArgs[0]); ?> is-invalid <?php unset($message);
if (isset($__messageOriginal)) { $message = $__messageOriginal; }
endif;
unset($__errorArgs, $__bag); ?>" placeholder="Kosongkan jika tidak ganti">
                                    <?php $__errorArgs = ['password'];
$__bag = $errors->getBag($__errorArgs[1] ?? 'default');
if ($__bag->has($__errorArgs[0])) :
if (isset($message)) { $__messageOriginal = $message; }
$message = $__bag->first($__errorArgs[0]); ?> <div class="invalid-feedback"><?php echo e($message); ?></div> <?php unset($message);
if (isset($__messageOriginal)) { $message = $__messageOriginal; }
endif;
unset($__errorArgs, $__bag); ?>
                                </div>
                                <div class="mb-3">
                                    <label class="small fw-bold mb-1">Konfirmasi Password</label>
                                    <input type="password" name="password_confirmation" class="form-control rounded-3 bg-light border-0" placeholder="Ulangi password baru">
                                </div>
                            </div>

                            
                            <div class="col-md-6 ps-md-4">
                                <h6 class="fw-bold text-dark mb-4 border-bottom pb-2">
                                    <i class="fas fa-shield-alt me-2 text-success"></i>Akses & Tim
                                </h6>

                                
                                <div class="mb-4 p-3 bg-primary bg-opacity-10 rounded-4 shadow-xs border border-primary border-opacity-10">
                                    <label class="small fw-bold d-block mb-1 text-primary">Unit Kerja / Tim:</label>
                                    <span class="h6 fw-bold mb-0 text-dark"><?php echo e($user->team->nama_tim ?? 'Lintas Tim'); ?></span>
                                </div>

                                
                                <input type="hidden" name="role" value="<?php echo e($user->role); ?>">
                                <input type="hidden" name="has_super_access" value="<?php echo e($user->has_super_access); ?>">

                                <div class="mt-5 pt-2">
                                    <button type="submit" class="btn btn-primary w-100 rounded-pill py-3 fw-bold shadow">
                                        <i class="fas fa-save me-2"></i> Simpan Perubahan
                                    </button>
                                </div>

                            </div>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>

<link rel="stylesheet" href="<?php echo e(asset('css/pages/profile-edit.css')); ?>">
<?php $__env->stopSection(); ?>
<?php echo $__env->make('layouts.app', array_diff_key(get_defined_vars(), ['__data' => 1, '__path' => 1]))->render(); ?><?php /**PATH /var/www/resources/views/profile/edit.blade.php ENDPATH**/ ?>