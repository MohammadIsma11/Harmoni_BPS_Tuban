<?php $__env->startSection('content'); ?>
<div class="container-fluid px-4">
    <div class="row justify-content-center">
        <div class="col-xl-8 col-lg-10">
            <div class="d-flex align-items-center mb-4 animate-up">
                <a href="<?php echo e(route('manajemen.mitra.index')); ?>" class="btn btn-light rounded-circle me-3 shadow-sm">
                    <i class="fas fa-arrow-left"></i>
                </a>
                <div>
                    <h3 class="fw-bold mb-0">Tambah Mitra Baru</h3>
                    <p class="text-muted small mb-0">Isi detail informasi untuk mendaftarkan mitra ke sistem.</p>
                </div>
            </div>

            <form action="<?php echo e(route('manajemen.mitra.store')); ?>" method="POST">
                <?php echo csrf_field(); ?>
                <div class="row g-4">
                    <!-- Column 1 -->
                    <div class="col-md-6">
                        <!-- Section: Identitas & Profil -->
                        <div class="card border-0 shadow-sm rounded-4 mb-4 animate-up" style="animation-delay: 0.1s;">
                            <div class="card-header bg-white border-0 py-3 ps-4">
                                <h6 class="fw-bold mb-0"><i class="fas fa-id-card text-primary me-2"></i>Identitas & Profil</h6>
                            </div>
                            <div class="card-body p-4 pt-0">
                                <div class="mb-3">
                                    <label class="form-label small fw-bold text-muted">SOBAT ID *</label>
                                    <input type="text" name="sobat_id" class="form-control rounded-3 bg-light border-0 <?php $__errorArgs = ['sobat_id'];
$__bag = $errors->getBag($__errorArgs[1] ?? 'default');
if ($__bag->has($__errorArgs[0])) :
if (isset($message)) { $__messageOriginal = $message; }
$message = $__bag->first($__errorArgs[0]); ?> is-invalid <?php unset($message);
if (isset($__messageOriginal)) { $message = $__messageOriginal; }
endif;
unset($__errorArgs, $__bag); ?>" value="<?php echo e(old('sobat_id')); ?>" placeholder="Contoh: 3522..." required>
                                    <?php $__errorArgs = ['sobat_id'];
$__bag = $errors->getBag($__errorArgs[1] ?? 'default');
if ($__bag->has($__errorArgs[0])) :
if (isset($message)) { $__messageOriginal = $message; }
$message = $__bag->first($__errorArgs[0]); ?> <div class="invalid-feedback"><?php echo e($message); ?></div> <?php unset($message);
if (isset($__messageOriginal)) { $message = $__messageOriginal; }
endif;
unset($__errorArgs, $__bag); ?>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label small fw-bold text-muted">NAMA LENGKAP *</label>
                                    <input type="text" name="nama_lengkap" class="form-control rounded-3 bg-light border-0 <?php $__errorArgs = ['nama_lengkap'];
$__bag = $errors->getBag($__errorArgs[1] ?? 'default');
if ($__bag->has($__errorArgs[0])) :
if (isset($message)) { $__messageOriginal = $message; }
$message = $__bag->first($__errorArgs[0]); ?> is-invalid <?php unset($message);
if (isset($__messageOriginal)) { $message = $__messageOriginal; }
endif;
unset($__errorArgs, $__bag); ?>" value="<?php echo e(old('nama_lengkap')); ?>" placeholder="Nama sesuai KTP" required>
                                    <?php $__errorArgs = ['nama_lengkap'];
$__bag = $errors->getBag($__errorArgs[1] ?? 'default');
if ($__bag->has($__errorArgs[0])) :
if (isset($message)) { $__messageOriginal = $message; }
$message = $__bag->first($__errorArgs[0]); ?> <div class="invalid-feedback"><?php echo e($message); ?></div> <?php unset($message);
if (isset($__messageOriginal)) { $message = $__messageOriginal; }
endif;
unset($__errorArgs, $__bag); ?>
                                </div>
                                <div class="row mb-3">
                                    <div class="col-md-6">
                                        <label class="form-label small fw-bold text-muted">JENIS KELAMIN</label>
                                        <select name="jenis_kelamin" class="form-select rounded-3 bg-light border-0">
                                            <option value="L" <?php echo e(old('jenis_kelamin') == 'L' ? 'selected' : ''); ?>>Laki-laki</option>
                                            <option value="P" <?php echo e(old('jenis_kelamin') == 'P' ? 'selected' : ''); ?>>Perempuan</option>
                                        </select>
                                    </div>
                                    <div class="col-md-6">
                                        <label class="form-label small fw-bold text-muted">PENDIDIKAN</label>
                                        <select name="pendidikan" class="form-select rounded-3 bg-light border-0">
                                            <option value="">-- Pilih Pendidikan --</option>
                                            <option value="TAMAT SD / SEDERAJAT">TAMAT SD / SEDERAJAT</option>
                                            <option value="TAMAT SMP / SEDERAJAT">TAMAT SMP / SEDERAJAT</option>
                                            <option value="TAMAT SMA / SEDERAJAT">TAMAT SMA / SEDERAJAT</option>
                                            <option value="TAMAT D1 / D2 / D3">TAMAT D1 / D2 / D3</option>
                                            <option value="TAMAT D4 / S1">TAMAT D4 / S1</option>
                                            <option value="TAMAT S2">TAMAT S2</option>
                                            <option value="TAMAT S3">TAMAT S3</option>
                                        </select>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- Section: Data Kelahiran -->
                        <div class="card border-0 shadow-sm rounded-4 mb-4 animate-up" style="animation-delay: 0.2s;">
                            <div class="card-header bg-white border-0 py-3 ps-4">
                                <h6 class="fw-bold mb-0"><i class="fas fa-calendar-day text-success me-2"></i>Data Kelahiran</h6>
                            </div>
                            <div class="card-body p-4 pt-0">
                                <div class="mb-3">
                                    <label class="form-label small fw-bold text-muted">TEMPAT LAHIR</label>
                                    <input type="text" name="tempat_lahir" class="form-control rounded-3 bg-light border-0" value="<?php echo e(old('tempat_lahir')); ?>" placeholder="Contoh: TUBAN">
                                </div>
                                <div class="row">
                                    <div class="col-md-7">
                                        <label class="form-label small fw-bold text-muted">TANGGAL LAHIR</label>
                                        <input type="date" name="tgl_lahir" class="form-control rounded-3 bg-light border-0" value="<?php echo e(old('tgl_lahir')); ?>">
                                    </div>
                                    <div class="col-md-5">
                                        <label class="form-label small fw-bold text-muted">UMUR</label>
                                        <input type="number" name="umur" class="form-control rounded-3 bg-light border-0" value="<?php echo e(old('umur')); ?>" placeholder="Thn">
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Column 2 -->
                    <div class="col-md-6">
                        <!-- Section: Pekerjaan & Posisi -->
                        <div class="card border-0 shadow-sm rounded-4 mb-4 animate-up" style="animation-delay: 0.3s;">
                            <div class="card-header bg-white border-0 py-3 ps-4">
                                <h6 class="fw-bold mb-0"><i class="fas fa-briefcase text-warning me-2"></i>Pekerjaan & Posisi</h6>
                            </div>
                            <div class="card-body p-4 pt-0">
                                <div class="mb-3">
                                    <label class="form-label small fw-bold text-muted">POSISI MITRA</label>
                                    <div class="d-flex flex-wrap gap-3 mt-1">
                                        <div class="form-check">
                                            <input class="form-check-input" type="checkbox" name="posisi[]" value="Mitra Pendataan" id="pos1">
                                            <label class="form-check-label small" for="pos1">Mitra Pendataan</label>
                                        </div>
                                        <div class="form-check">
                                            <input class="form-check-input" type="checkbox" name="posisi[]" value="Mitra Pengawasan" id="pos2">
                                            <label class="form-check-label small" for="pos2">Mitra Pengawasan</label>
                                        </div>
                                        <div class="form-check">
                                            <input class="form-check-input" type="checkbox" name="posisi[]" value="Mitra Pengolahan" id="pos3">
                                            <label class="form-check-label small" for="pos3">Mitra Pengolahan</label>
                                        </div>
                                    </div>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label small fw-bold text-muted">POSISI DAFTAR</label>
                                    <input type="text" name="posisi_daftar" class="form-control rounded-3 bg-light border-0" value="<?php echo e(old('posisi_daftar')); ?>" placeholder="Contoh: Petugas Pendataan Lapangan">
                                </div>
                                <div class="mb-3">
                                    <label class="form-label small fw-bold text-muted">PEKERJAAN UTAMA</label>
                                    <input type="text" name="pekerjaan" class="form-control rounded-3 bg-light border-0" value="<?php echo e(old('pekerjaan')); ?>" placeholder="Contoh: Petani, Wiraswasta">
                                </div>
                                <div class="mb-0">
                                    <label class="form-label small fw-bold text-muted">DESKRIPSI PEKERJAAN LAIN</label>
                                    <textarea name="deskripsi_pekerjaan_lain" class="form-control rounded-3 bg-light border-0" rows="2" placeholder="Detail pekerjaan lainnya..."><?php echo e(old('deskripsi_pekerjaan_lain')); ?></textarea>
                                </div>
                            </div>
                        </div>

                        <!-- Section: Kontak & Domisili -->
                        <div class="card border-0 shadow-sm rounded-4 mb-4 animate-up" style="animation-delay: 0.4s;">
                            <div class="card-header bg-white border-0 py-3 ps-4">
                                <h6 class="fw-bold mb-0"><i class="fas fa-map-marker-alt text-danger me-2"></i>Kontak & Alamat</h6>
                            </div>
                            <div class="card-body p-4 pt-0">
                                <div class="row mb-3">
                                    <div class="col-md-6">
                                        <label class="form-label small fw-bold text-muted">EMAIL</label>
                                        <input type="email" name="email" class="form-control rounded-3 bg-light border-0" value="<?php echo e(old('email')); ?>" placeholder="email@example.com">
                                    </div>
                                    <div class="col-md-6">
                                        <label class="form-label small fw-bold text-muted">NO TELP</label>
                                        <input type="text" name="no_telp" class="form-control rounded-3 bg-light border-0" value="<?php echo e(old('no_telp')); ?>" placeholder="08...">
                                    </div>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label small fw-bold text-muted">ALAMAT DETAIL</label>
                                    <textarea name="alamat_detail" class="form-control rounded-3 bg-light border-0" rows="2" placeholder="Nama Jalan, RT/RW, Dusun..."><?php echo e(old('alamat_detail')); ?></textarea>
                                </div>
                                <div class="row g-2 mb-0">
                                    <div class="col-md-6 mb-2">
                                        <label class="form-label small fw-bold text-muted text-uppercase" style="font-size: 0.65rem;">Provinsi</label>
                                        <input type="text" name="alamat_prov" class="form-control form-control-sm rounded-3 bg-light border-0" value="<?php echo e(old('alamat_prov', 'JAWA TIMUR')); ?>">
                                    </div>
                                    <div class="col-md-6 mb-2">
                                        <label class="form-label small fw-bold text-muted text-uppercase" style="font-size: 0.65rem;">Kabupaten</label>
                                        <input type="text" name="alamat_kab" class="form-control form-control-sm rounded-3 bg-light border-0" value="<?php echo e(old('alamat_kab', 'TUBAN')); ?>">
                                    </div>
                                    <div class="col-md-6 mb-2">
                                        <label class="form-label small fw-bold text-muted text-uppercase" style="font-size: 0.65rem;">Kecamatan</label>
                                        <input type="text" name="alamat_kec" class="form-control form-control-sm rounded-3 bg-light border-0" value="<?php echo e(old('alamat_kec')); ?>" placeholder="Kecamatan">
                                    </div>
                                    <div class="col-md-6 mb-2">
                                        <label class="form-label small fw-bold text-muted text-uppercase" style="font-size: 0.65rem;">Desa/Kelurahan</label>
                                        <input type="text" name="alamat_desa" class="form-control form-control-sm rounded-3 bg-light border-0" value="<?php echo e(old('alamat_desa')); ?>" placeholder="Desa">
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- Section: Administrasi BPS -->
                        <div class="card border-0 shadow-sm rounded-4 mb-4 animate-up" style="animation-delay: 0.5s;">
                            <div class="card-header bg-white border-0 py-3 ps-4">
                                <h6 class="fw-bold mb-0"><i class="fas fa-cog text-secondary me-2"></i>Administrasi BPS</h6>
                            </div>
                            <div class="card-body p-4 pt-0">
                                <div class="mb-3">
                                    <label class="form-label small fw-bold text-muted">STATUS SELEKSI</label>
                                    <select name="status_seleksi" class="form-select rounded-3 bg-light border-0">
                                        <option value="Diterima" <?php echo e(old('status_seleksi') == 'Diterima' ? 'selected' : ''); ?>>Diterima</option>
                                        <option value="Ditolak" <?php echo e(old('status_seleksi') == 'Ditolak' ? 'selected' : ''); ?>>Ditolak</option>
                                        <option value="Menunggu Konfirmasi" <?php echo e(old('status_seleksi') == 'Menunggu Konfirmasi' ? 'selected' : ''); ?>>Menunggu Konfirmasi</option>
                                    </select>
                                </div>
                                <div class="mb-0">
                                    <label class="form-label small fw-bold text-muted">PLAFON HONOR BULANAN *</label>
                                    <div class="input-group">
                                        <span class="input-group-text bg-light border-0 text-muted">Rp</span>
                                        <input type="number" name="max_honor_bulanan" class="form-control rounded-end-3 bg-light border-0" value="<?php echo e(old('max_honor_bulanan', 3200000)); ?>" required>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="d-flex justify-content-end gap-2 mt-2 mb-5 animate-up" style="animation-delay: 0.6s;">
                    <a href="<?php echo e(route('manajemen.mitra.index')); ?>" class="btn btn-light rounded-pill px-4 text-muted fw-bold">Batal</a>
                    <button type="submit" class="btn btn-primary rounded-pill px-5 fw-bold shadow-sm">
                        <i class="fas fa-save me-2"></i>Simpan Mitra
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<style>
    .animate-up { animation: fadeInUp 0.5s ease-out backwards; }
    @keyframes fadeInUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
    .card { transition: transform 0.2s; }
    .card:hover { transform: translateY(-5px); }
</style>
<?php $__env->stopSection(); ?>

<?php echo $__env->make('layouts.app', array_diff_key(get_defined_vars(), ['__data' => 1, '__path' => 1]))->render(); ?><?php /**PATH /var/www/resources/views/manajemen/mitra/create.blade.php ENDPATH**/ ?>