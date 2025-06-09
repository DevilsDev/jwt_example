// Fetch CSRF token for AJAX forms (per session)
let csrfToken = '';
fetch('/api/csrf-token')
    .then(res => res.json())
    .then(data => { csrfToken = data.csrfToken; });

// Signup handler
if (document.getElementById('signupForm')) {
    document.getElementById('signupForm').onsubmit = async e => {
        e.preventDefault();
        const username = e.target.username.value;
        const password = e.target.password.value;
        // Send signup request
        const res = await fetch('/api/signup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'CSRF-Token': csrfToken // Protects against CSRF
            },
            body: JSON.stringify({ username, password }),
        });
        const data = await res.json();
        document.getElementById('msg').textContent = data.message;
        if (res.ok) setTimeout(() => window.location = '/login.html', 1000);
    };
}

// Login handler
if (document.getElementById('loginForm')) {
    document.getElementById('loginForm').onsubmit = async e => {
        e.preventDefault();
        const username = e.target.username.value;
        const password = e.target.password.value;
        const remember = e.target.remember.checked;
        // Send login request
        const res = await fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'CSRF-Token': csrfToken
            },
            body: JSON.stringify({ username, password, remember }),
        });
        const data = await res.json();
        document.getElementById('msg').textContent = data.message;
        if (res.ok) setTimeout(() => window.location = '/dashboard.html', 500);
    };
}

// Dashboard authentication/refresh token logic
if (window.location.pathname.endsWith('dashboard.html')) {
    // Helper: Try to get dashboard data, if unauthorized try refresh, else redirect to login
    function fetchDashboard() {
        fetch('/api/dashboard')
            .then(r => r.json())
            .then(data => {
                if (data.user) {
                    document.getElementById('dashboardMsg').textContent = data.message;
                } else {
                    // Try refresh token if not authorized
                    fetch('/api/refresh', { method: 'POST', credentials: 'include', headers: { 'CSRF-Token': csrfToken } })
                        .then(rr => rr.json())
                        .then(rrdata => {
                            if (rrdata.message === 'Token refreshed') fetchDashboard();
                            else window.location = '/login.html';
                        })
                        .catch(() => window.location = '/login.html');
                }
            })
            .catch(() => window.location = '/login.html');
    }
    fetchDashboard();

    document.getElementById('logoutBtn').onclick = async () => {
        await fetch('/api/logout', { method: 'POST', headers: { 'CSRF-Token': csrfToken } });
        window.location = '/login.html';
    };
}
