document.addEventListener('DOMContentLoaded', function() {
    // Init Tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return bootstrap.Tooltip.getOrCreateInstance(tooltipTriggerEl);
    });

    const modalAbsensiElement = document.getElementById('modalInputAbsensi');
    if (!modalAbsensiElement) return;

    const modalAbsensi = bootstrap.Modal.getOrCreateInstance(modalAbsensiElement);
    const formAbsensi = document.getElementById('formAbsensi');
    const methodField = document.getElementById('methodField');
    const btnDelete = document.getElementById('btnDeleteAbsensi');
    const formDelete = document.getElementById('formDelete');

    // Filter Berhalangan
    $('#btnFilterCuti').on('click', function() {
        $(this).toggleClass('filter-active');
        const isFiltering = $(this).hasClass('filter-active');
        $('.pegawai-row').each(function() {
            const val = $(this).data('has-leave');
            const hasLeave = (val === true || val === 'true');
            if (isFiltering) {
                $(this).toggle(hasLeave);
            } else {
                $(this).show();
            }
        });
    });

    // Edit Klik Bar
    $(document).on('click', '.btn-edit-absensi', function() {
        // Hide tooltip immediately so it doesn't float over modal
        const tip = bootstrap.Tooltip.getInstance(this);
        if (tip) tip.hide();

        const data = $(this).data();
        const id = data.id;

        $('#modalTitle').html('<i class="fas fa-edit me-2 text-warning"></i>Edit Data Kehadiran');
        
        let updateUrl = window.absensiRoutes.update.replace(':id', id);
        formAbsensi.action = updateUrl;
        methodField.innerHTML = '<input type="hidden" name="_method" value="PUT">';

        const rawStart = (data.startDate || data.start || '').toString();
        const rawEnd = (data.endDate || data.end || '').toString();
        const cleanStart = rawStart.split('T')[0].split(' ')[0];
        const cleanEnd = rawEnd.split('T')[0].split(' ')[0];

        $('#edit_user_id').val(data.userId);
        $('#edit_start_date').val(cleanStart);
        $('#edit_end_date').val(cleanEnd);
        $('#edit_status').val(data.status);
        $('#edit_keterangan').val(data.ket);

        btnDelete.classList.remove('d-none');
        btnDelete.dataset.id = id;
        modalAbsensi.show();
    });

    // Delete Handle (Swal renders cleanly over modal due to z-index: 2000)
    btnDelete.addEventListener('click', function() {
        const id = this.dataset.id;
        if (!id) return;

        Swal.fire({
            title: 'Hapus Data Kehadiran?',
            text: "Data ini akan dihapus permanen dari sistem!",
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#ef4444',
            cancelButtonColor: '#64748b',
            confirmButtonText: 'Ya, Hapus!',
            cancelButtonText: 'Batal'
        }).then((result) => {
            if (result.isConfirmed) {
                modalAbsensi.hide();
                let deleteUrl = window.absensiRoutes.destroy.replace(':id', id);
                formDelete.action = deleteUrl;
                formDelete.submit();
            }
        });
    });

    // Reset Form when Modal is Closed
    modalAbsensiElement.addEventListener('hidden.bs.modal', function () {
        $('#modalTitle').html('<i class="fas fa-user-edit me-2 text-primary"></i>Input Manual');
        formAbsensi.action = window.absensiRoutes.store;
        methodField.innerHTML = '';
        formAbsensi.reset();
        btnDelete.classList.add('d-none');
        btnDelete.dataset.id = '';
    });

    // New Input button trigger
    $('[data-bs-target="#modalInputAbsensi"]').on('click', function() {
        $('#modalTitle').html('<i class="fas fa-user-edit me-2 text-primary"></i>Input Manual');
        formAbsensi.action = window.absensiRoutes.store;
        methodField.innerHTML = '';
        formAbsensi.reset();
        btnDelete.classList.add('d-none');
        btnDelete.dataset.id = '';
    });
});

