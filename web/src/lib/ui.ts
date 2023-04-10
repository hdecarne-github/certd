export function navbarNavigate() {
	document.querySelectorAll('a.nav-link').forEach((navLink) => {
		const href = new URL(navLink.getAttribute('href')??'.', location.href).href
		if (href == location.href) {
			navLink.classList.add('active');
			navLink.setAttribute('aria-current', 'page');
		} else {
			navLink.classList.remove('active');
			navLink.removeAttribute('aria-current');
		}
	});
}

const ui = {
	navbarNavigate,
};

export default ui;