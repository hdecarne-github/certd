export function navigate() {
    document.querySelectorAll('a.nav-link').forEach((navLink) => {
        if (navLink.getAttribute('href') == location.pathname) {
            navLink.classList.add('active')
            navLink.setAttribute('aria-current', 'page')
        } else {
            navLink.classList.remove('active')
            navLink.removeAttribute('aria-current')
        }
    })
}