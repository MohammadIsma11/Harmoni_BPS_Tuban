<?php $__env->startSection('content'); ?>
<link rel="stylesheet" href="<?php echo e(asset('css/pages/history-edit.css')); ?>">
<?php $__env->startPush('styles'); ?>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
<style>
    #task-map {
        height: 280px;
        width: 100%;
        border-radius: 12px;
        border: 2px solid #e2e8f0;
        z-index: 1;
    }
    .gps-btn-container {
        display: flex;
        gap: 8px;
        margin-top: 10px;
    }
</style>
<?php $__env->stopPush(); ?>

<div class="container-fluid">
    <?php
        // 1. Pecah string Lokasi dari Report
        $currentLocation = $report->lokasi_tujuan;
        $currentDesa = '';
        $currentKec = '';
        if (str_contains($currentLocation, ', Kec. ')) {
            $parts = explode(', Kec. ', $currentLocation);
            $currentKec = trim($parts[1] ?? '');
            $currentDesa = trim(str_replace('Desa ', '', $parts[0] ?? ''));
        }

        // 2. LOGIKA TANGGAL PELAKSANAAN
        $valTanggal = \Carbon\Carbon::parse($report->tanggal_lapor)->format('Y-m-d');

        // 3. DATA VALIDASI UNTUK JS
        $userCuti = \App\Models\Absensi::where('user_id', $agenda->assigned_to)
                ->whereIn('status', ['CT', 'CST1']) 
                ->get(['start_date', 'end_date', 'status']);

        $laporanTerpakai = \App\Models\Agenda::where('assigned_to', $agenda->assigned_to)
                ->where('id', '!=', $agenda->id) 
                ->whereNotNull('tanggal_pelaksanaan')
                ->where('status_laporan', 'Selesai')
                ->pluck('tanggal_pelaksanaan')
                ->toArray();
    ?>

    <div class="row justify-content-center">
        <div class="col-md-11 mt-4">
            <div class="card border-0 shadow-sm rounded-4 mb-4 overflow-hidden">
                <div class="bg-warning p-3 d-flex align-items-center justify-content-between">
                    <div class="d-flex align-items-center">
                        <div class="bg-white bg-opacity-25 p-2 rounded-3 me-3 text-white">
                            <i class="fas fa-edit fa-lg"></i>
                        </div>
                        <div>
                            <h5 class="text-white fw-bold mb-0">Perbarui Laporan Translok</h5>
                            <small class="text-white text-opacity-75">Sesuaikan data laporan translok yang sudah dikirim</small>
                        </div>
                    </div>
                    <span class="badge bg-white text-warning rounded-pill px-3 shadow-sm fw-bold">MODE EDIT</span>
                </div>
            </div>

            <form id="formLaporan" action="<?php echo e(route('history.update', $report->id)); ?>" method="POST" enctype="multipart/form-data">
                <?php echo csrf_field(); ?>
                <?php echo method_field('PUT'); ?>

                <div class="row">
                    
                    <div class="col-lg-5">
                        <div class="card border-0 shadow-sm rounded-4 p-4 mb-4 bg-light">
                            <h6 class="fw-bold mb-3 text-muted border-bottom pb-2"><i class="fas fa-lock me-2"></i>Informasi Baku</h6>
                            <div class="mb-3">
                                <label class="form-label small fw-bold text-muted text-uppercase">Nama Kegiatan</label>
                                <textarea class="form-control border-0 bg-white fw-bold rounded-3" rows="2" readonly style="resize: none;"><?php echo e($agenda->title); ?></textarea>
                            </div>
                            <div class="mb-0">
                                <label class="form-label small fw-bold text-muted text-uppercase">Nomor Surat Tugas</label>
                                <input type="text" class="form-control border-0 bg-white fw-bold rounded-3 text-primary" value="<?php echo e($agenda->nomor_surat_tugas ?? '-'); ?>" readonly>
                            </div>
                        </div>

                        <div class="card border-0 shadow-sm rounded-4 p-4 mb-4 border-start border-4 border-primary">
                            <h6 class="fw-bold mb-3 text-primary"><i class="fas fa-map-marked-alt me-2"></i>Perbarui Lokasi</h6>
                            
                            
                            <div class="mb-3">
                                <label class="form-label small fw-bold text-muted text-uppercase">Tandai Lokasi di Peta <span class="text-danger">*</span></label>
                                <div id="task-map"></div>
                                <div class="gps-btn-container">
                                    <button type="button" id="btn-gps" class="btn btn-primary btn-sm w-100 rounded-pill fw-bold shadow-sm">
                                        <i class="fas fa-location-arrow me-1"></i> Gunakan GPS Saya
                                    </button>
                                </div>
                                <div class="form-text text-muted" style="font-size: 0.7rem;">
                                    <i class="fas fa-info-circle me-1"></i> Klik peta untuk memindahkan pin lokasi.
                                </div>
                            </div>

                            <div class="mb-3">
                                <label class="form-label small fw-bold text-muted text-uppercase">Kecamatan <span class="text-danger">*</span></label>
                                <select name="kecamatan" id="kecamatan" class="form-select rounded-3 border-0 bg-light p-3 fw-bold" required>
                                    <option value="">-- Pilih Kecamatan --</option>
                                    <?php $__currentLoopData = ["BANCAR", "BANGILAN", "GRABAGAN", "JATIROGO", "JENU", "KENDURUAN", "KEREK", "MERAKURAK", "MONTONG", "PALANG", "PARENGAN", "PLUMPANG", "RENGEL", "SEMANDING", "SENORI", "SINGGAHAN", "SOKO", "TAMBAKBOYO", "TUBAN", "WIDANG"]; $__env->addLoop($__currentLoopData); foreach($__currentLoopData as $kec): $__env->incrementLoopIndices(); $loop = $__env->getLastLoop(); ?>
                                        <option value="<?php echo e($kec); ?>" <?php echo e((old('kecamatan', $currentKec) == $kec) ? 'selected' : ''); ?>><?php echo e($kec); ?></option>
                                    <?php endforeach; $__env->popLoop(); $loop = $__env->getLastLoop(); ?>
                                </select>
                            </div>
                            
                            <div class="mb-3">
                                <label class="form-label small fw-bold text-muted text-uppercase">Desa / Kelurahan <span class="text-danger">*</span></label>
                                <select name="desa" id="desa" class="form-select rounded-3 border-0 bg-light p-3 fw-bold" required>
                                    <option value="">-- Pilih Desa --</option>
                                </select>
                            </div>

                            <div class="mb-0">
                                <label class="form-label small fw-bold text-muted text-uppercase">Nama SLS / Blok / RT / RW (Auto-deteksi)</label>
                                <input type="text" name="sls" id="sls" class="form-control rounded-3 border-0 bg-light p-3 fw-bold shadow-sm" placeholder="Contoh: RT 02 / RW 01" value="<?php echo e(old('sls', $report->sls)); ?>">
                            </div>

                            <input type="hidden" name="lat" id="lat" value="<?php echo e(old('lat', $report->lat)); ?>">
                            <input type="hidden" name="lng" id="lng" value="<?php echo e(old('lng', $report->lng)); ?>">
                        </div>

                        <div class="card border-0 shadow-sm rounded-4 p-4 mb-4 border-start border-4 border-warning">
                            <h6 class="fw-bold mb-3 text-warning"><i class="fas fa-calendar-check me-2"></i>Waktu Pelaksanaan</h6>
                            <div class="mb-3">
                                <label class="form-label small fw-bold text-dark text-uppercase">Tanggal Pelaksanaan Lapangan <span class="text-danger">*</span></label>
                                <input type="date" name="tanggal_pelaksanaan" id="tanggal_pelaksanaan" class="form-control rounded-3 shadow-sm border-warning fw-bold" 
                                       min="<?php echo e(\Carbon\Carbon::parse($agenda->event_date)->format('Y-m-d')); ?>" 
                                       max="<?php echo e(\Carbon\Carbon::parse($agenda->end_date)->format('Y-m-d')); ?>" 
                                       value="<?php echo e($valTanggal); ?>" required>
                            </div>
                            <div class="mb-0">
                                <label class="form-label small fw-bold text-dark text-uppercase">Ganti Foto Dokumentasi</label>
                                <input type="file" name="fotos[]" id="foto_upload" class="form-control" accept="image/*" multiple>
                                <div class="form-text text-danger fw-bold" style="font-size: 0.65rem;">
                                    * Upload foto baru akan mengganti semua foto lama.
                                </div>
                                <div class="d-flex flex-wrap gap-2 mt-3 p-2 bg-light rounded-3 border border-dashed">
                                    <?php $__empty_1 = true; $__currentLoopData = $agenda->photos; $__env->addLoop($__currentLoopData); foreach($__currentLoopData as $photo): $__env->incrementLoopIndices(); $loop = $__env->getLastLoop(); $__empty_1 = false; ?>
                                        <div class="position-relative border rounded-2 overflow-hidden shadow-sm" style="width: 55px; height: 55px;">
                                            <img src="<?php echo e(asset('storage/' . $photo->photo_path)); ?>" class="w-100 h-100 object-fit-cover">
                                        </div>
                                    <?php endforeach; $__env->popLoop(); $loop = $__env->getLastLoop(); if ($__empty_1): ?>
                                        <small class="text-muted">Tidak ada foto lama.</small>
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>
                    </div>

                    
                    <div class="col-lg-7">
                        <div class="card border-0 shadow-sm rounded-4 p-4 h-100">
                            <h6 class="fw-bold mb-4 border-bottom pb-2 text-dark"><i class="fas fa-clipboard-check me-2 text-success"></i>Detail Hasil Pengawasan</h6>
                            
                            <div class="mb-4">
                                <label class="form-label fw-bold small text-secondary">RESPONDEN / PETUGAS DITEMUI <span class="text-danger">*</span></label>
                                <input type="text" name="responden" class="form-control rounded-3 bg-light border-0 p-3" required value="<?php echo e(old('responden', $details['responden'] ?? ($agenda->responden ?? ''))); ?>">
                            </div>

                            <div class="mb-4">
                                <label class="form-label fw-bold small text-secondary">AKTIVITAS DILAKUKAN <span class="text-danger">*</span></label>
                                <textarea name="aktivitas" class="form-control rounded-3 bg-light border-0 p-3" rows="6" required><?php echo e(old('aktivitas', $details['aktivitas'] ?? ($agenda->aktivitas ?? ''))); ?></textarea>
                            </div>

                            <div class="mb-4">
                                <label class="form-label fw-bold small text-secondary">PERMASALAHAN LAPANGAN <span class="text-danger">*</span></label>
                                <textarea name="permasalahan" class="form-control rounded-3 bg-light border-0 p-3" rows="3" required><?php echo e(old('permasalahan', $details['permasalahan'] ?? ($agenda->permasalahan ?? ''))); ?></textarea>
                            </div>

                            <div class="mb-4">
                                <label class="form-label fw-bold small text-success text-uppercase">Solusi / Tindak Lanjut <span class="text-danger">*</span></label>
                                <textarea name="solusi_antisipasi" class="form-control rounded-3 bg-light border-0 p-3" rows="3" required><?php echo e(old('solusi_antisipasi', $details['solusi_antisipasi'] ?? ($agenda->solusi_antisipasi ?? ''))); ?></textarea>
                            </div>

                            <div class="d-flex justify-content-between align-items-center pt-3 border-top mt-auto">
                                <a href="<?php echo e(route('history.index')); ?>" class="btn btn-light px-4 rounded-pill fw-bold text-muted">Batal</a>
                                <button type="submit" id="btnSubmit" class="btn btn-warning px-5 rounded-pill fw-bold shadow-lg text-white">
                                    <i class="fas fa-save me-2"></i> Update Laporan
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </form>
        </div>
    </div>
</div>

<script>
    window.daftarCuti = <?php echo json_encode($userCuti, 15, 512) ?>;
    window.laporanTerpakai = <?php echo json_encode($laporanTerpakai, 15, 512) ?>;
    window.tanggalAwal = "<?php echo e($valTanggal); ?>";
    window.initialDesa = <?php echo json_encode(old('desa', $currentDesa), 512) ?>;
</script>
<script src="<?php echo e(asset('js/pages/history-edit.js')); ?>"></script>
<?php $__env->startPush('scripts'); ?>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
    document.addEventListener('DOMContentLoaded', function() {
        // Initialize Leaflet Map
        const map = L.map('task-map').setView([-6.89, 112.06], 11);
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '&copy; OpenStreetMap contributors'
        }).addTo(map);

        let marker = null;
        let kecData = null;
        let desaData = null;
        let slsData = null;

        // Load GeoJSONs
        Promise.all([
            fetch('<?php echo e(asset("geojson/kecamatan.geojson")); ?>').then(r => r.json()),
            fetch('<?php echo e(asset("geojson/desa.geojson")); ?>').then(r => r.json()),
            fetch('<?php echo e(asset("geojson/peta_sls_202513523.geojson")); ?>').then(r => r.json()).catch(() => null)
        ]).then(([kec, desa, sls]) => {
            kecData = kec;
            desaData = desa;
            slsData = sls;
            console.log("Map boundaries loaded successfully.");
            
            // If there's old inputs or default coordinate, restore them
            const oldLat = $('#lat').val();
            const oldLng = $('#lng').val();
            if (oldLat && oldLng) {
                updateMarker(parseFloat(oldLat), parseFloat(oldLng), false);
            }
        });

        function isInside(pt, vs) {
            let x = pt.lng, y = pt.lat;
            let inside = false;
            for (let i = 0, j = vs.length - 1; i < vs.length; j = i++) {
                let xi = vs[i][0], yi = vs[i][1];
                let xj = vs[j][0], yj = vs[j][1];
                let intersect = ((yi > y) != (yj > y)) && (x < (xj - xi) * (y - yi) / (yj - yi) + xi);
                if (intersect) inside = !inside;
            }
            return inside;
        }

        function checkGeometry(geometry, pt) {
            if (geometry.type === 'Polygon') {
                return isInside(pt, geometry.coordinates[0]);
            } else if (geometry.type === 'MultiPolygon') {
                return geometry.coordinates.some(poly => isInside(pt, poly[0]));
            }
            return false;
        }

        function findLocationDetails(lat, lng) {
            let res = { kec: null, desa: null, sls: null };
            const point = L.latLng(lat, lng);

            if (kecData) {
                for (const f of kecData.features) {
                    if (checkGeometry(f.geometry, point)) {
                        res.kec = f.properties.nmkec;
                        break;
                    }
                }
            }

            if (desaData && res.kec) {
                for (const f of desaData.features) {
                    if (f.properties.kec_desa.startsWith(res.kec.toUpperCase() + '_')) {
                        if (checkGeometry(f.geometry, point)) {
                            res.desa = f.properties.kec_desa.split('_')[1];
                            break;
                        }
                    }
                }
            }

            if (slsData && res.desa) {
                for (const f of slsData.features) {
                    if (f.properties.nmkec.toUpperCase() === res.kec.toUpperCase() && f.properties.nmdesa.toUpperCase() === res.desa.toUpperCase()) {
                        if (checkGeometry(f.geometry, point)) {
                            res.sls = f.properties.nmsls;
                            break;
                        }
                    }
                }
            }

            return res;
        }

        function updateMarker(lat, lng, doAutoFill = true) {
            $('#lat').val(lat);
            $('#lng').val(lng);

            if (marker) {
                marker.setLatLng([lat, lng]);
            } else {
                marker = L.marker([lat, lng], { draggable: true }).addTo(map);
                marker.on('dragend', function(e) {
                    const pos = marker.getLatLng();
                    updateMarker(pos.lat, pos.lng, true);
                });
            }
            map.setView([lat, lng], 16);

            if (doAutoFill) {
                const details = findLocationDetails(lat, lng);
                if (details.kec) {
                    const kecEl = document.getElementById('kecamatan');
                    kecEl.value = details.kec.toUpperCase();
                    kecEl.dispatchEvent(new Event('change'));

                    // Manually populate Desa options to ensure they exist immediately without race conditions
                    const desaEl = document.getElementById('desa');
                    desaEl.innerHTML = '<option value="">-- Pilih Desa --</option>';
                    desaEl.disabled = false;

                    const localDataWilayah = {
                        "BANCAR": ["Jatisari", "Kayen", "Sukoharjo", "Sidomulyo", "Cingklung", "Margosuko", "Ngampelrejo", "Pugoh", "Karangrejo", "Sumberan", "Siding", "Tengger Klon", "Ngujuran", "Tlogoagung", "Latsari", "Sukolilo", "Bulujowo", "Bulumeduro", "Banjarejo", "Tergambang", "Sembungin", "Boncong", "Bogorejo", "Bancar"],
                        "BANGILAN": ["Klakeh", "Bate", "Kablukan", "Ngrojo", "Weden", "Sidokumpul", "Sidotentrem", "Bangilan", "Kedunghardjo", "Kedungmulyo", "Banjarworo", "Sidodadi", "Kedungjambangan", "Kumpulrejo"],
                        "GRABAGAN": ["Ngarum", "Ngrejeng", "Banyubang", "Grabagan", "Waleran", "Gesikan", "Ngandong", "Dahor", "Dermawuhhardjo", "Menyunyur", "Pakis"],
                        "JATIROGO": ["Karangtengah", "Jombok", "Wotsogo", "Sidomulyo", "Jatiklabang", "Dingil", "Demit", "Sugihan", "Sadang", "Bader", "Paseyan", "Kebonharjo", "Wangi", "Ketodan", "Besowo", "Ngepon", "Kedungmakam", "Sekaran"],
                        "JENU": ["Karangasem", "Socorejo", "Temaji", "Purworejo", "Tasikharjo", "Remen", "Mentoso", "Rawasan", "Sumurgeneng", "Wadung", "Kaliuntu", "Beji", "Suwalan", "Jenggolo", "Sekardadi", "Jenu", "Sugihwaras"],
                        "KENDURUAN": ["Sokogunung", "Jamprong", "Bendonglateng", "Sidorejo", "Sokogrenjeng", "Sidohasri", "Sidomukti", "Tawaran", "Jlodro"],
                        "KEREK": ["Gemulung", "Wolutengah", "Trantang", "Sidonganti", "Tengger Wetan", "Hargoretno", "Temayang", "Padasan", "Karanglo", "Sumberarum", "Margomulyo", "Jarorejo", "Margorejo", "Gaji", "Kedungrejo", "Kasiman", "Mliwang"],
                        "MERAKURAK": ["Kapu", "Tegalrejo", "Tahulu", "Mandirejo", "Bogorejo", "Sumberejo", "Sendanghaji", "Sambonggede", "Sumber", "Tuwiri Wetan", "Tuwiri Kulon", "Borehbangle", "Senori", "Sembungrejo", "Pongpongan", "Temandang", "Tlogowaru", "Tobo", "Sugihan"],
                        "MONTONG": ["Manjung", "Tanggulangin", "Sumurgung", "Bringin", "Maindu", "Jetak", "Talun", "Pucangan", "Pakel", "Montongsekar", "Talangkembar", "Nguluhan", "Guwoterus"],
                        "PALANG": ["Ngimbang", "Wangun", "Ketambul", "Cepokorejo", "Pliwetan", "Karangagung", "Leran Wetan", "Leran Kulon", "Glodog", "Palang", "Gesikharjo", "Pucangan", "Cendoro", "Dawung", "Tegalbang", "Sumurgung", "Kradenan", "Tasikmadu", "Panyuran"],
                        "PARENGAN": ["Kemlaten", "Mergoasri", "Kumpulrejo", "Cengkong", "Brangkal", "Mergorejo", "Selogabus", "Sendangrejo", "Mojomalang", "Sugihwaras", "Suciharjo", "Pacing", "Parangbatu", "Sukorejo", "Sembung", "Ngawun", "Wukirharjo", "Dagangan"],
                        "PLUMPANG": ["Trutup", "Kesamben", "Kepohagung", "Kedungrojo", "Cangkring", "Sembungrejo", "Plandirejo", "Bandungrejo", "Klotok", "Kebomlati", "Kedungsoko", "Penidon", "Magersari", "Jatimulyo", "Plumpang", "Sumurjalak", "Ngrayung", "Sumberagung"],
                        "RENGEL": ["Kebonagung", "Bulurejo", "Karangtinoto", "Tambakrejo", "Kanorejo", "Ngadirejo", "Sumberejo", "Campurejo", "Banjararum", "Prambon Wetan", "Banjaragung", "Punggulrejo", "Rengel", "Sawahan", "Maibit", "Pekuwon"],
                        "SEMANDING": ["Ngino", "Bektiharjo", "Sambongrejo", "Genaharjo", "Gesing", "Tunah", "Kowang", "Penambangan", "Semanding", "Prunggahan Wetan", "Prunggahan Kulon", "Jadi", "Boto", "Tegalagung", "Bejagung", "Gedongombo", "Karang"],
                        "SENORI": ["Banyuurip", "Wonosari", "Katerban", "Rayung", "Sidoharjo", "Wanglu Wetan", "Wanglu Kulon", "Leran", "Kaligede", "Jatisari", "Medalem", "Sendang"],
                        "SINGGAHAN": ["Binangun", "Saringembat", "Kedungjambe", "Tunggulrejo", "Tanjungrejo", "Lajo Kidul", "Tanggir", "Mergosari", "Mulyorejo", "Tingkis", "Mulyoagung", "Lajo Lor"],
                        "SOKO": ["Menilo", "Simo", "Kendalrejo", "Mojoagung", "Pandanwangi", "Glagahsari", "Kenongosari", "Sandingrowo", "Rahayu", "Sokosari", "Bangunrejo", "Mentoro", "Pandanagung", "Prambontergayang", "Jati", "Cekalang", "Tluwe", "Wadung", "Klumpit", "Jegulo", "Sumurcinde", "Nguruan", "Gununganyar"],
                        "TAMBAKBOYO": ["Nguluhan", "Dikir", "Mander", "Plajan", "Belikanget", "Cokrowati", "Sotang", "Pulogede", "Gadon", "Pabeyan", "Tambakboyo", "Klutuk", "Dasin", "Kenanti", "Sobontoro", "Sawir", "Merkawang", "Glondonggede"],
                        "TUBAN": ["Sumurgung", "Sugiharjo", "Kembangbilo", "Mondokan", "Perbon", "Latsari", "Sidorejo", "Doromukti", "Kebonsari", "Sukolilo", "Baturetno", "Sendangharjo", "Kutorejo", "Sidomulyo", "Ronggomulyo", "Kingking", "Karangsari"],
                        "WIDANG": ["Patihan", "Ngadipuro", "Ngadirejo", "Bunut", "Widang", "Compreng", "Banjar", "Tegalsari", "Kedungharjo", "Tegalrejo", "Simorejo", "Mrutuk", "Minohorejo", "Sumberejo", "Mlangi", "Kujung"]
                    };

                    const selectedKec = details.kec.toUpperCase();
                    const listDesa = localDataWilayah[selectedKec] || [];
                    [...listDesa].sort().forEach(desa => {
                        const option = document.createElement('option');
                        option.value = desa;
                        option.text = desa;
                        desaEl.add(option);
                    });

                    if (details.desa) {
                        const targetDesa = details.desa.toUpperCase();
                        let matchedValue = '';
                        for (let i = 0; i < desaEl.options.length; i++) {
                            if (desaEl.options[i].value.toUpperCase() === targetDesa) {
                                matchedValue = desaEl.options[i].value;
                                break;
                            }
                        }
                        if (matchedValue) {
                            desaEl.value = matchedValue;
                        } else {
                            desaEl.value = details.desa;
                        }
                        desaEl.dispatchEvent(new Event('change'));
                    }
                }
                if (details.sls) {
                    $('#sls').val(details.sls);
                } else {
                    $('#sls').val('');
                }
            }
        }

        map.on('click', function(e) {
            updateMarker(e.latlng.lat, e.latlng.lng, true);
        });

        $('#btn-gps').on('click', function() {
            if (navigator.geolocation) {
                navigator.geolocation.getCurrentPosition(function(position) {
                    const lat = position.coords.latitude;
                    const lng = position.coords.longitude;
                    updateMarker(lat, lng, true);
                }, function(error) {
                    Swal.fire('GPS Error', 'Gagal mendeteksi lokasi GPS Anda.', 'error');
                });
            } else {
                Swal.fire('Error', 'Browser Anda tidak mendukung Geolocation.', 'error');
            }
        });

        // Form submit validation
        $('form').on('submit', function(e) {
            const lat = $('#lat').val();
            const lng = $('#lng').val();
            if (!lat || !lng) {
                e.preventDefault();
                Swal.fire({
                    icon: 'warning',
                    title: 'Lokasi Belum Dipilih',
                    text: 'Silakan tandai lokasi Anda di peta terlebih dahulu!'
                });
            }
        });
    });
</script>
<?php $__env->stopPush(); ?>
<?php $__env->stopSection(); ?>
<?php echo $__env->make('layouts.app', array_diff_key(get_defined_vars(), ['__data' => 1, '__path' => 1]))->render(); ?><?php /**PATH /var/www/resources/views/history/edit.blade.php ENDPATH**/ ?>