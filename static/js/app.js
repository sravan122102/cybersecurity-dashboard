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

let isAutoAttackScheduled = false;

function showDashboard() {
    loginView.classList.remove('active');
    dashboardView.classList.add('active');
    document.getElementById('user-role').textContent = `Role: ${state.role}`;
    
    loadDashboardData();
    initWebSocket();
    
    if (!isAutoAttackScheduled) {
        scheduleNextAttack();
        isAutoAttackScheduled = true;
    }
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

// Auto-Simulate Attack every 2 to 3 minutes (runs entirely on frontend)
function scheduleNextAttack() {
    const delay = Math.floor(Math.random() * (180000 - 120000 + 1)) + 120000;
    
    setTimeout(() => {
        if (state.token) {
            const companies = ['Alpha', 'Beta', 'Gamma'];
            const threats = ['Massive DDoS Attack', 'Ransomware Encryption', 'Zero-Day Exploit', 'Database Exfiltration', 'Advanced Persistent Threat'];
            
            const attackedCompany = companies[Math.floor(Math.random() * companies.length)];
            const threat = threats[Math.floor(Math.random() * threats.length)];
            
            // Reset all to secure first
            companies.forEach(company => {
                const el = document.getElementById(`status-${company}`);
                if(el) {
                    el.textContent = 'Secure';
                    el.className = 'value status-badge status-Secure';
                }
            });
            
            // Flash the attacked company red
            const el = document.getElementById(`status-${attackedCompany}`);
            if(el) {
                el.textContent = 'Under Attack';
                el.className = 'value status-badge status-Critical';
            }
            
            // Show alert toast
            showToast(`🚨 CRITICAL: Company ${attackedCompany} is under attack! (${threat})`);
            
            // Reset back to Secure after 30 seconds
            setTimeout(() => {
                const resetEl = document.getElementById(`status-${attackedCompany}`);
                if(resetEl && resetEl.textContent === 'Under Attack') {
                    resetEl.textContent = 'Secure';
                    resetEl.className = 'value status-badge status-Secure';
                }
            }, 30000);
        }
        scheduleNextAttack();
    }, delay);
}

// WebSocket connection (for background detection alerts)
function initWebSocket() {
    if(state.socket) return;
    
    try {
        state.socket = io({
            extraHeaders: { 'Authorization': `Bearer ${state.token}` }
        });
        
        state.socket.on('new_alert', (alert) => {
            if (alert.source_ip) {
                showToast(`⚠️ DETECTED: ${alert.threat_type} from ${alert.source_ip}`);
            }
        });
    } catch(err) {
        console.log('WebSocket not available, using frontend-only mode.');
    }
}

function showToast(msg) {
    const container = document.getElementById('alert-toast-container');
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.style.cssText = 'background: linear-gradient(135deg, #ef4444, #b91c1c); color: white; padding: 20px; font-size: 1.1rem; font-weight: bold; border-radius: 10px; margin-bottom: 10px; box-shadow: 0 5px 20px rgba(239,68,68,0.5); animation: slideIn 0.3s ease;';
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
            const tbody = document.getElementById('rules-tbody');
            tbody.innerHTML = '';
            rules.forEach(r => {
                const tr = document.createElement('tr');
                const timeWindow = r.time_window_seconds >= 60 ? `${r.time_window_seconds / 60} min` : `${r.time_window_seconds}s`;
                tr.innerHTML = `
                    <td><strong>${r.name}</strong><br><small style="color: var(--text-secondary);">${r.description}</small></td>
                    <td><code style="background: var(--bg-dark); padding: 3px 8px; border-radius: 4px; font-size: 0.8rem;">${r.event_type}</code></td>
                    <td class="severity-${r.severity}">${r.severity}</td>
                    <td>${r.threshold} events</td>
                    <td>${timeWindow}</td>
                    <td>${(r.confidence * 100).toFixed(0)}%</td>
                `;
                tbody.appendChild(tr);
            });
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

// Auto-refresh active tabs every 5 seconds to show live background data
setInterval(() => {
    if (state.token) {
        if (document.getElementById('threats-content').classList.contains('active')) {
            loadThreats();
        } else if (document.getElementById('logs-content').classList.contains('active')) {
            loadLogs();
        }
    }
}, 5000);

init();
