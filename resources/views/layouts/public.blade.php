<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ $title ?? 'SEpintu - BPS Kabupaten Tuban' }}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary-color: #0058a8;
            --secondary-color: #00aaff;
            --bg-light: #f8fbff;
        }
        body {
            font-family: 'Plus Jakarta Sans', sans-serif;
            background-color: var(--bg-light);
            color: #2d3436;
        }
        .navbar {
            background: white;
            box-shadow: 0 2px 15px rgba(0,0,0,0.05);
            padding: 1rem 0;
        }
        .navbar-brand img { height: 40px; }
        .btn-primary {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
            border-radius: 10px;
            padding: 0.6rem 1.5rem;
            font-weight: 600;
        }
        .card {
            border: none;
            border-radius: 20px;
            box-shadow: 0 10px 30px rgba(0,88,168,0.05);
        }
        .footer {
            padding: 3rem 0;
            background: white;
            margin-top: 5rem;
        }
    </style>
    @yield('styles')
</head>
<body>
    <nav class="navbar navbar-expand-lg sticky-top">
        <div class="container">
            <a class="navbar-brand d-flex align-items-center" href="/">
                <img src="{{ asset('img/logo-bps.png') }}" alt="Logo" class="me-2" onerror="this.src='https://upload.wikimedia.org/wikipedia/commons/2/28/Lambang_Badan_Pusat_Statistik_%28BPS%29_Indonesia.svg'">
                <div class="lh-1">
                    <div class="fw-bold text-primary fs-5">SEpintu</div>
                    <small class="text-muted" style="font-size: 0.7rem;">BPS KABUPATEN TUBAN</small>
                </div>
            </a>
            <button class="navbar-toggler border-0" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto align-items-center">
                    <li class="nav-item">
                        <a class="nav-link px-3 fw-medium" href="{{ route('ticket.public.create') }}">Buat Tiket</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link px-3 fw-medium" href="{{ route('ticket.public.index') }}">Tiket Saya</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link px-3 fw-medium" href="{{ route('ticket.public.track.form') }}">Lacak Tiket</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link px-3 fw-medium" href="{{ route('kms.public.index') }}">Knowledge Base</a>
                    </li>
                    <li class="nav-item ms-lg-3">
                        <a class="btn btn-primary" href="{{ route('login') }}">
                            <i class="fas fa-sign-in-alt me-2"></i>Login Pegawai
                        </a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <main class="py-5">
        @yield('content')
    </main>

    <footer class="footer">
        <div class="container text-center">
            <p class="mb-0 text-muted small">&copy; {{ date('Y') }} Badan Pusat Statistik Kabupaten Tuban. Hak Cipta Dilindungi.</p>
        </div>
    </footer>

    <!-- Floating Consultation Trigger -->
    <button type="button" class="floating-wa shadow-lg border-0" data-bs-toggle="modal" data-bs-target="#consultationModal">
        <i class="fas fa-headset me-2"></i> Konsultasi Cepat
    </button>

    <!-- Consultation Modal -->
    <div class="modal fade" id="consultationModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content border-0 rounded-4 shadow-lg overflow-hidden">
                <div id="consultation-header" class="modal-header bg-success text-white p-4">
                    <h5 class="modal-title fw-bold"><i class="fas fa-headset me-2"></i> Layanan Konsultasi</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body p-4 p-md-5">
                    <p class="text-muted mb-4 small fw-bold text-uppercase tracking-widest" style="letter-spacing: 1px;">Silakan pilih media konsultasi yang Anda inginkan.</p>
                    
                    <!-- Media Selector -->
                    <div class="mb-4">
                        <div class="row g-2">
                            <div class="col-6">
                                <input type="radio" class="btn-check" name="consultation_method" id="method-wa" value="wa" checked>
                                <label class="btn btn-outline-success w-100 py-3 rounded-4 fw-bold d-flex align-items-center justify-content-center" for="method-wa">
                                    <i class="fab fa-whatsapp me-2 fs-5"></i> WhatsApp
                                </label>
                            </div>
                            <div class="col-6">
                                <input type="radio" class="btn-check" name="consultation_method" id="method-zoom" value="zoom">
                                <label class="btn btn-outline-primary w-100 py-3 rounded-4 fw-bold d-flex align-items-center justify-content-center" for="method-zoom">
                                    <i class="fas fa-video me-2 fs-5"></i> Zoom Meeting
                                </label>
                            </div>
                        </div>
                    </div>

                    <!-- Input Nama -->
                    <div class="mb-3">
                        <label class="form-label small fw-bold">Nama Anda</label>
                        <input type="text" id="consultation_name" class="form-control rounded-4 p-3 bg-light border-0" placeholder="Masukkan nama Anda...">
                    </div>

                    <!-- WhatsApp Specific Inputs -->
                    <div id="wa-inputs-section">
                        <div class="mb-4">
                            <label class="form-label small fw-bold">Kategori Bantuan</label>
                            <select id="wa_category" class="form-select rounded-4 p-3 bg-light border-0">
                                <option value="" disabled selected>Pilih Kategori</option>
                                <option value="Rekrutmen SE">Rekrutmen SE</option>
                                <option value="Lapangan SE">Lapangan SE</option>
                                <option value="Aplikasi FASIH">Aplikasi FASIH</option>
                                <option value="Lainnya">Lainnya</option>
                            </select>
                        </div>
                    </div>

                    <!-- Zoom Specific Card (Initially hidden) -->
                    <div id="zoom-details-section" class="d-none">
                        <div class="card bg-primary bg-opacity-10 border border-primary border-opacity-25 rounded-4 p-4 mb-4">
                            <div class="d-flex align-items-center mb-3">
                                <div class="bg-primary text-white rounded-circle p-2 d-inline-block me-3">
                                    <i class="fas fa-video"></i>
                                </div>
                                <div>
                                    <h6 class="fw-bold mb-0 text-primary">Virtual Room BPS Tuban</h6>
                                    <small class="text-muted">Konsultasi Tatap Muka Online</small>
                                </div>
                            </div>
                            <hr class="my-2 opacity-25">
                            <p class="small mb-2 fw-medium text-dark">
                                Yuk, mulai konsultasi tatap muka secara online dengan menekan tombol di bawah! Anda akan terhubung secara instan, aman, dan langsung dengan petugas layanan BPS Kabupaten Tuban.
                            </p>
                            <p class="text-muted small mb-0" style="font-size: 0.75rem;">
                                <i class="fas fa-info-circle me-1"></i> Pastikan aplikasi Zoom sudah terinstal di perangkat Anda untuk kenyamanan konsultasi terbaik.
                            </p>
                        </div>
                    </div>

                    <button type="button" id="btn-submit-consultation" onclick="startConsultation()" class="btn btn-success w-100 py-3 rounded-pill fw-bold text-uppercase shadow-sm">
                        Mulai Chat WA
                    </button>
                </div>
            </div>
        </div>
    </div>

    <style>
        .floating-wa {
            position: fixed;
            bottom: 30px;
            right: 30px;
            background: linear-gradient(135deg, #0058a8 0%, #00aaff 100%);
            color: white;
            padding: 15px 25px;
            border-radius: 50px;
            font-weight: 700;
            text-decoration: none;
            z-index: 9999;
            display: flex;
            align-items: center;
            transition: all 0.3s;
            box-shadow: 0 10px 25px rgba(0, 88, 168, 0.2);
        }
        .floating-wa:hover {
            transform: scale(1.05);
            box-shadow: 0 15px 30px rgba(0, 88, 168, 0.35);
            color: white;
        }
        .modal-content {
            backdrop-filter: blur(10px);
            background: rgba(255, 255, 255, 0.95);
        }
    </style>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <script>
        // Switch between WA and Zoom in Landing page
        document.addEventListener('change', function(e) {
            if (e.target && e.target.name === 'consultation_method') {
                const method = e.target.value;
                const waInputs = document.getElementById('wa-inputs-section');
                const zoomDetails = document.getElementById('zoom-details-section');
                const header = document.getElementById('consultation-header');
                const submitBtn = document.getElementById('btn-submit-consultation');
                
                if (method === 'zoom') {
                    waInputs.classList.add('d-none');
                    zoomDetails.classList.remove('d-none');
                    header.classList.remove('bg-success');
                    header.classList.add('bg-primary');
                    submitBtn.classList.remove('btn-success');
                    submitBtn.classList.add('btn-primary');
                    submitBtn.textContent = 'Gabung Zoom Meeting';
                } else {
                    waInputs.classList.remove('d-none');
                    zoomDetails.classList.add('d-none');
                    header.classList.remove('bg-primary');
                    header.classList.add('bg-success');
                    submitBtn.classList.remove('btn-primary');
                    submitBtn.classList.add('btn-success');
                    submitBtn.textContent = 'Mulai Chat WA';
                }
            }
        });

        function startConsultation() {
            const name = document.getElementById('consultation_name').value || 'User';
            const method = document.querySelector('input[name="consultation_method"]:checked').value;

            if (method === 'zoom') {
                const zoomLink = '{{ \App\Models\Setting::getValue('zoom_link', 'https://zoom.us/j/85755461223?pwd=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx') }}';
                window.open(zoomLink, '_blank');
                
                const modalEl = document.getElementById('consultationModal');
                const modal = bootstrap.Modal.getInstance(modalEl) || new bootstrap.Modal(modalEl);
                modal.hide();
            } else {
                const category = document.getElementById('wa_category').value;
                if (!category) {
                    alert('Silakan pilih kategori terlebih dahulu.');
                    return;
                }

                const text = `Halo Call Center BPS Tuban, saya ${name} ingin berkonsultasi mengenai *${category}*.`;
                const encodedText = encodeURIComponent(text);
                window.open(`https://wa.me/6285755461223?text=${encodedText}`, '_blank');
                
                const modalEl = document.getElementById('consultationModal');
                const modal = bootstrap.Modal.getInstance(modalEl) || new bootstrap.Modal(modalEl);
                modal.hide();
            }
        }
    </script>
    @yield('scripts')
</body>
</html>
