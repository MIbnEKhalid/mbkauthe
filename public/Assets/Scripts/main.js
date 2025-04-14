function getCookieValue(cookieName) {
    const cookies = document.cookie.split('; ');
    for (let cookie of cookies) {
        const [name, value] = cookie.split('=');
        if (name === cookieName) {
            return decodeURIComponent(value);
        }
    }
    return null; // Return null if the cookie is not found
}

function loadpage(url){
    window.location.href = url;
}

function formatDate(date) {
    return new Date(date).toLocaleString('en-GB', { day: '2-digit', month: '2-digit', year: 'numeric', hour: 'numeric', minute: 'numeric', second: 'numeric', hour12: true });
}

function scrollToHash() {
    const headerHeight = document.querySelector('header').offsetHeight;
    const url = new URL(window.location.href);
    const targetId = url.hash.substring(1);
    if (targetId) {
        const targetElement = document.getElementById(targetId);
        if (targetElement) {
            const targetPosition = targetElement.offsetTop - headerHeight - 100; // Adjust 90px as needed
            window.scrollTo({top: targetPosition, behavior: 'smooth'});
        }
    }
}