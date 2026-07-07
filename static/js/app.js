const state = {
    token: localStorage.getItem('token'),
    role: null,
    socket: null
};

// UI Elements
const loginView = document.getElementById('login-view');
const dashboardView = document.getElementById('dashboard-view');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
const loginBtn = document.getElementById('login-btn');
const logoutBtn = document.getElementById('logout-btn');
const loginError = document.getElementById('login-error');

// Initialization
async function init() {
    if (state.token) {
        await fetchUser();
    } else {
        showLogin();
    }
}

// Authentication
loginBtn.addEventListener('click', async () => {
    const username = usernameInput.value;
    const password = passwordInput.value;
    
    try {
        const res = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        
        if (res.ok) {
            state.token = data.token;
            state.role = data.role;
            localStorage.setItem('token', data.token);
            loginError.textContent = '';
            showDashboard();
        } else {
            loginError.textContent = data.message;
        }
    } catch (e) {
        console.error("Login Error:", e);
        loginError.textContent = 'Server error. Try again.';
    }
});

passwordInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        loginBtn.click();
    }
});

logoutBtn.addEventListener('click', () => {
    state.token = null;
    state.role = null;
    localStorage.removeItem('token');
    if(state.socket) state.socket.disconnect();
    showLogin();
});

async function fetchUser() {
    try {
        const res = await fetch('/api/auth/me', {
            headers: { 'Authorization': `Bearer ${state.token}` }
        });
        if (res.ok) {
            const data = await res.json();
            state.role = data.role;
            showDashboard();
        } else {
            logoutBtn.click();
        }
    } catch (e) {
        logoutBtn.click();
    }
}

// Navigation
function showLogin() {
    loginView.classList.add('active');
    dashboardView.classList.remove('active');
}

function showDashboard() {
    loginView.classList.remove('active');
    dashboardView.classList.add('active');
    document.getElementById('user-role').textContent = `Role: ${state.role}`;
    
    loadDashboardData();
    initWebSocket();
    setInterval(loadDashboardData, 30000); // refresh every 30s
}

// Dashboard Data Loading
async function authFetch(url) {
    const res = await fetch(url, {
        headers: { 'Authorization': `Bearer ${state.token}` }
    });
    if(res.status === 401) logoutBtn.click();
    return res.json();
}

async function loadDashboardData() {
    // Reset all statuses to Secure on load
    ['Alpha', 'Beta', 'Gamma'].forEach(company => {
        const el = document.getElementById(`status-${company}`);
        if(el) {
            el.textContent = 'Secure';
            el.className = 'value status-badge status-Secure';
        }
    });
}

document.getElementById('simulate-attack-btn').addEventListener('click', async () => {
    try {
        await fetch('/api/simulate-attack', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${state.token}` }
        });
    } catch(err) {
        console.error(err);
    }
});

// WebSocket connection
function initWebSocket() {
    if(state.socket) return;
    
    state.socket = io({
        extraHeaders: { 'Authorization': `Bearer ${state.token}` }
    });
    
    state.socket.on('new_alert', (alert) => {
        if (alert.company) {
            // Simulated Attack on a Company
            showToast(`🚨 CRITICAL: ${alert.company} is under attack! (${alert.threat_type})`);
            
            // Reset all to secure first, then highlight the attacked one
            ['Alpha', 'Beta', 'Gamma'].forEach(company => {
                const el = document.getElementById(`status-${company}`);
                if(el) {
                    el.textContent = 'Secure';
                    el.className = 'value status-badge status-Secure';
                }
            });
            
            // Highlight the attacked company
            const el = document.getElementById(`status-${alert.company}`);
            if(el) {
                el.textContent = 'Under Attack';
                el.className = 'value status-badge status-Critical';
            }
        } else {
            // Generic background detection alert
            showToast(`⚠️ DETECTED: ${alert.threat_type} from ${alert.source_ip}`);
        }
    });
}

function showToast(msg) {
    const container = document.getElementById('alert-toast-container');
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.style.backgroundColor = '#ef4444';
    toast.style.color = 'white';
    toast.style.padding = '20px';
    toast.style.fontSize = '1.2rem';
    toast.style.fontWeight = 'bold';
    toast.textContent = msg;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 8000);
}

// Sidebar Navigation
const sidebarLinks = document.querySelectorAll('#sidebar-nav li');
const pageContents = document.querySelectorAll('.page-content');

sidebarLinks.forEach(link => {
    link.addEventListener('click', (e) => {
        sidebarLinks.forEach(l => l.classList.remove('active'));
        pageContents.forEach(c => c.classList.remove('active'));
        
        e.target.classList.add('active');
        const viewId = e.target.getAttribute('data-view');
        document.getElementById(viewId).classList.add('active');
        document.getElementById('page-title').textContent = e.target.textContent;
    });
});

// Notification Dropdown
const notifBtn = document.getElementById('notif-bell');
const notifDropdown = document.getElementById('notif-dropdown');
const notifList = document.getElementById('notif-list');

notifBtn.addEventListener('click', async (e) => {
    if (e.target.closest('.notif-dropdown')) return;
    
    notifDropdown.classList.toggle('show');
    if (notifDropdown.classList.contains('show')) {
        try {
            const alerts = await authFetch('/api/alerts');
            notifList.innerHTML = '';
            if (alerts.length === 0) {
                notifList.innerHTML = '<div class="notif-item">No active alerts.</div>';
            } else {
                alerts.forEach(alert => {
                    const item = document.createElement('div');
                    item.className = 'notif-item';
                    item.innerHTML = `<strong>[${alert.severity}] ${alert.threat_type}</strong>Source IP: ${alert.source_ip}<br><small>${new Date(alert.timestamp).toLocaleString()}</small>`;
                    notifList.appendChild(item);
                });
            }
        } catch(err) {
            console.error(err);
        }
    }
});

document.addEventListener('click', (e) => {
    if (!e.target.closest('#notif-bell')) {
        notifDropdown.classList.remove('show');
    }
});

// Phase 2 functionality
async function loadThreats() {
    const severity = document.getElementById('threat-filter-severity').value;
    let url = '/api/threats';
    if (severity) url += `?severity=${severity}`;
    
    try {
        const threats = await authFetch(url);
        const tbody = document.getElementById('threats-tbody');
        tbody.innerHTML = '';
        threats.forEach(t => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${new Date(t.timestamp).toLocaleString()}</td>
                <td><strong>${t.threat_type}</strong></td>
                <td>${t.source_ip}</td>
                <td class="severity-${t.severity}">${t.severity}</td>
                <td>${(t.confidence * 100).toFixed(0)}%</td>
                <td>${t.mitigation_step || '-'}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch(err) { console.error(err); }
}

async function loadLogs() {
    const ip = document.getElementById('log-filter-ip').value;
    const severity = document.getElementById('log-filter-severity').value;
    let url = '/api/logs/search?';
    if (ip) url += `source_ip=${encodeURIComponent(ip)}&`;
    if (severity) url += `severity=${severity}`;
    
    try {
        const logs = await authFetch(url);
        const tbody = document.getElementById('logs-tbody');
        tbody.innerHTML = '';
        logs.forEach(l => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${new Date(l.timestamp).toLocaleString()}</td>
                <td>${l.source_ip}</td>
                <td>${l.location || 'Unknown'}</td>
                <td>${l.event_type}</td>
                <td class="severity-${l.severity}">${l.severity}</td>
                <td style="word-break: break-all; max-width: 300px;">${l.raw_message}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch(err) { console.error(err); }
}

async function loadSettings() {
    try {
        const res = await fetch('/api/rules', { headers: { 'Authorization': `Bearer ${state.token}` } });
        if(res.ok) {
            const rules = await res.json();
            document.getElementById('rules-content').textContent = JSON.stringify(rules, null, 2);
        }
    } catch(err) { console.error(err); }
    
    try {
        const res = await fetch('/api/users', { headers: { 'Authorization': `Bearer ${state.token}` } });
        if(res.ok) {
            const users = await res.json();
            const tbody = document.getElementById('users-tbody');
            tbody.innerHTML = '';
            users.forEach(u => {
                const tr = document.createElement('tr');
                const locked = u.locked_until ? `Locked until ${new Date(u.locked_until).toLocaleTimeString()}` : 'Active';
                tr.innerHTML = `
                    <td>${u.username}</td>
                    <td>${u.role}</td>
                    <td>${locked}</td>
                `;
                tbody.appendChild(tr);
            });
        }
    } catch(err) { console.error(err); }
}

sidebarLinks.forEach(link => {
    link.addEventListener('click', (e) => {
        const viewId = e.target.getAttribute('data-view');
        if (viewId === 'threats-content') loadThreats();
        else if (viewId === 'logs-content') loadLogs();
        else if (viewId === 'settings-content') loadSettings();
    });
});

init();
