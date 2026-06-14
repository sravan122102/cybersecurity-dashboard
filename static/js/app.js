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


    // Load Summary
    const summary = await authFetch('/api/stats/summary');
    document.getElementById('val-logs').textContent = summary.total_logs_24h;
    document.getElementById('val-threats').textContent = summary.total_threats_24h;
    document.getElementById('val-alerts').textContent = summary.active_alerts;
    document.getElementById('notif-badge').textContent = summary.active_alerts;
    if (summary.active_alerts > 0) {
        document.getElementById('notif-badge').style.display = 'inline-block';
    } else {
        document.getElementById('notif-badge').style.display = 'none';
    }
    
    const statusEl = document.getElementById('val-status');
    statusEl.textContent = summary.system_status;
    statusEl.className = `value status-badge status-${summary.system_status}`;
    
    // Load Top Sources
    const sources = await authFetch('/api/stats/top_sources');
    const tbody = document.querySelector('#sources-table tbody');
    tbody.innerHTML = '';
    sources.forEach(s => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${s.source_ip}</td><td>${s.count}</td>`;
        tbody.appendChild(tr);
    });
    
    // Load Recent Activity
    const activity = await authFetch('/api/stats/recent_activity');
    const feed = document.getElementById('activity-feed');
    feed.innerHTML = '';
    activity.forEach(a => addFeedItem(a, false));
    
    // Load Timeline Chart
    const timeline = await authFetch('/api/stats/timeline');
    renderChart(timeline);
}

function addFeedItem(log, prepend=true) {
    const feed = document.getElementById('activity-feed');
    const item = document.createElement('div');
    item.className = 'feed-item';
    const time = new Date(log.timestamp).toLocaleTimeString();
    item.innerHTML = `
        <span class="time">${time}</span>
        <span class="ip">${log.source_ip}</span>
        <span class="event severity-${log.severity}">${log.event_type}</span>
    `;
    if (prepend) {
        feed.prepend(item);
        if(feed.children.length > 50) feed.lastChild.remove();
    } else {
        feed.appendChild(item);
    }
}

let chartInstance = null;
function renderChart(data) {
    const ctx = document.getElementById('timelineChart').getContext('2d');
    
    const labels = Object.keys(data).sort();
    const criticalData = labels.map(l => data[l].CRITICAL);
    const highData = labels.map(l => data[l].HIGH);
    const mediumData = labels.map(l => data[l].MEDIUM);
    
    if(chartInstance) chartInstance.destroy();
    
    chartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                { label: 'Critical', data: criticalData, borderColor: '#ef4444', tension: 0.4 },
                { label: 'High', data: highData, borderColor: '#f59e0b', tension: 0.4 },
                { label: 'Medium', data: mediumData, borderColor: '#3b82f6', tension: 0.4 }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { labels: { color: '#94a3b8' } }
            },
            scales: {
                x: { ticks: { color: '#94a3b8' }, grid: { color: '#334155' } },
                y: { ticks: { color: '#94a3b8' }, grid: { color: '#334155' } }
            }
        }
    });
}

// WebSocket connection
function initWebSocket() {
    if(state.socket) return;
    
    state.socket = io({
        extraHeaders: { 'Authorization': `Bearer ${state.token}` }
    });
    
    state.socket.on('new_alert', (alert) => {
        showToast(`🚨 NEW ALERT: ${alert.threat_type} from ${alert.source_ip}`);
        // Refresh summary
        loadDashboardData();
    });
}

function showToast(msg) {
    const container = document.getElementById('alert-toast-container');
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.textContent = msg;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 5000);
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
