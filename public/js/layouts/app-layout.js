function syncSidebar() {
    const currentPath = window.location.pathname;
    
    // Reset All: Hapus kelas active dan text-primary lama
    $('.sidebar .nav-link').removeClass('active text-primary');
    
    // Cari yang benar-benar pas (Exact Match)
    $('.sidebar a.nav-link').each(function() {
        const href = $(this).attr('href');
        if (href) {
            try {
                const linkPath = new URL(href, window.location.origin).pathname;
                
                // Jika path sama persis
                if (linkPath === currentPath) {
                    $(this).addClass('active');
                    
                    // Buka parent collapse jika ada
                    const parentCollapse = $(this).closest('.collapse');
                    if (parentCollapse.length) {
                        parentCollapse.addClass('show');
                        const toggleBtn = parentCollapse.prev('.nav-link');
                        toggleBtn.removeClass('collapsed').addClass('text-primary');
                    }
                }
            } catch(e) { }
        }
    });

    // Special Case: Dashboard
    if (currentPath === '/' || currentPath === '/dashboard') {
        $('.sidebar a[href*="dashboard"]').addClass('active');
    }
}

function initCoreLayout() {
    // 2. Global Sidebar Toggle (Universal)
    const isHidden = localStorage.getItem('sidebarHidden') === 'true';
    if (isHidden && window.innerWidth > 992) {
        $('body').addClass('sidebar-hidden');
    }

    $('#global-sidebar-toggle').off('click').on('click', function() {
        if (window.innerWidth > 992) {
            $('body').toggleClass('sidebar-hidden');
            localStorage.setItem('sidebarHidden', $('body').hasClass('sidebar-hidden'));
        } else {
            $('#sidebar').toggleClass('active');
        }
    });

    // 3. Sidebar Dropdown Persistence (LocalStorage)
    const openMenus = JSON.parse(localStorage.getItem('sidebarOpenMenus') || '[]');
    
    $('.collapse').each(function() {
        const id = $(this).attr('id');
        if (openMenus.includes(id) || $(this).hasClass('show')) {
            $(this).addClass('show');
            $(this).prev('.nav-link').removeClass('collapsed');
        } else {
            $(this).removeClass('show');
            $(this).prev('.nav-link').addClass('collapsed');
        }
    });

    $('.collapse').off('shown.bs.collapse hidden.bs.collapse').on('shown.bs.collapse hidden.bs.collapse', function() {
        const currentOpen = $('.collapse.show').map(function() { return $(this).attr('id'); }).get();
        localStorage.setItem('sidebarOpenMenus', JSON.stringify(currentOpen));
        
        if ($(this).hasClass('show')) {
            $(this).prev('.nav-link').removeClass('collapsed');
        } else {
            $(this).prev('.nav-link').addClass('collapsed');
        }
    });

    // Sync sidebar state with current URL
    syncSidebar();
}

/**
 * Universal Modal Sanitization & Anti-Freeze Handler
 * Prevents modals from being trapped in child CSS stacking contexts
 * and cleans up any orphaned/duplicate backdrops that cause grey screens.
 */
function cleanupModalBackdrops() {
    const hasVisibleModal = document.querySelectorAll('.modal.show').length > 0;
    if (!hasVisibleModal) {
        document.querySelectorAll('.modal-backdrop').forEach(function(el) {
            el.remove();
        });
        document.body.classList.remove('modal-open');
        document.documentElement.classList.remove('modal-open');
        document.body.style.overflow = '';
        document.body.style.paddingRight = '';
    }
}

function relocateModalsToBody() {
    document.querySelectorAll('.modal').forEach(function(modalEl) {
        if (modalEl.parentElement !== document.body) {
            document.body.appendChild(modalEl);
        }
    });
}

$(document).ready(function() {
    initCoreLayout();
    relocateModalsToBody();
    cleanupModalBackdrops();

    // Remove transform from .animate-fade-in on animationend to prevent any stacking context issues
    const animatedContent = document.querySelector('.content-padding.animate-fade-in');
    if (animatedContent) {
        animatedContent.addEventListener('animationend', function() {
            this.style.transform = 'none';
        });
    }

    // Global listeners for any Bootstrap modals in the app
    $(document).on('show.bs.modal', '.modal', function() {
        if (this.parentElement !== document.body) {
            document.body.appendChild(this);
        }
    });

    $(document).on('hidden.bs.modal hide.bs.modal', '.modal', function() {
        setTimeout(cleanupModalBackdrops, 150);
        setTimeout(cleanupModalBackdrops, 350);
    });

    // Safeguard on Escape key
    $(document).on('keydown', function(e) {
        if (e.key === 'Escape' || e.keyCode === 27) {
            setTimeout(cleanupModalBackdrops, 200);
        }
    });
});


