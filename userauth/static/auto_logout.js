// static/js/auto_logout.js
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

const csrftoken = getCookie('csrftoken');

function handleLogout() {
    fetch('/ajax-logout/', {
        method: 'POST',
        headers: {
            'X-CSRFToken': csrftoken,
            'X-Requested-With': 'XMLHttpRequest'
        }
    });
}

// Handle window/tab close
window.addEventListener('beforeunload', function (e) {
    handleLogout();
});

// Handle visibility change (when switching tabs)
document.addEventListener('visibilitychange', function() {
    if (document.visibilityState === 'hidden') {
        handleLogout();
    }
});