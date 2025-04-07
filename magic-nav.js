document.addEventListener('DOMContentLoaded', function() {
    const nav = document.querySelector('.magic-nav');
    const indicator = document.querySelector('.magic-indicator');
    const navItems = document.querySelectorAll('.magic-nav .nav-item');

    function moveIndicator(el) {
        indicator.style.left = el.offsetLeft + 'px';
        indicator.style.width = el.offsetWidth + 'px';
    }

    navItems.forEach(item => {
        item.addEventListener('mouseenter', function() {
            moveIndicator(this);
        });
        item.addEventListener('mouseleave', function() {
            const active = nav.querySelector('.nav-item .nav-link.active');
            if (active) {
                moveIndicator(active.parentNode);
            } else {
                indicator.style.width = '0';
            }
        });
    });

    // Opcional: Marca el enlace activo al cargar la página
    const currentPath = window.location.pathname;
    navItems.forEach(item => {
        const link = item.querySelector('a');
        if (link && link.getAttribute('href') === currentPath) {
            link.classList.add('active');
            moveIndicator(item);
        }
    });
});