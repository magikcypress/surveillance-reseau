// Variables globales
let socket;
let latencyChart;
let currentUser = null;

// Initialisation
document.addEventListener('DOMContentLoaded', () => {
    console.log('Initialisation de l\'application...');
    initializeCharts();
    setupEventListeners();

    // Vérifier l'URL pour la navigation initiale
    const hash = window.location.hash.substring(1) || 'login';
    if (hash === 'login' || !currentUser) {
        showPage('login');
    } else {
        showPage(hash);
    }

    checkAuth();
    startSessionCheck();
});

// Configuration des événements
function setupEventListeners() {
    console.log('Configuration des événements...');

    // Formulaire de connexion
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }

    // Navigation
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', handleNavigation);
    });

    // Déconnexion
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', handleLogout);
    }

    // Test de vitesse
    const speedTestBtn = document.getElementById('startSpeedTest');
    if (speedTestBtn) {
        speedTestBtn.addEventListener('click', startSpeedTest);
    }

    // Scanner le réseau
    const scanBtn = document.getElementById('scanNetworkBtn');
    if (scanBtn) {
        scanBtn.addEventListener('click', scanNetwork);
    }

    // Formulaire de rapport
    const reportForm = document.getElementById('reportForm');
    if (reportForm) {
        reportForm.addEventListener('submit', generateReport);
    }
}

// Gestion de l'authentification
async function checkAuth() {
    try {
        const token = localStorage.getItem('token');
        if (!token) {
            showPage('login');
            return;
        }

        // Vérifier d'abord la session
        const sessionResponse = await fetch('/api/auth/check', {
            method: 'GET',
            credentials: 'include'
        });

        if (!sessionResponse.ok) {
            handleSessionExpired();
            return;
        }

        // Vérifier ensuite le token
        const response = await fetch('/api/auth/verify', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            credentials: 'include'
        });

        if (!response.ok) {
            handleSessionExpired();
            return;
        }

        const data = await response.json();
        currentUser = data;

        // Vérifier si la session expire bientôt
        if (data.sessionExpires) {
            const expiresAt = new Date(data.sessionExpires);
            const now = new Date();
            const timeUntilExpiry = expiresAt - now;

            // Si la session expire dans moins de 5 minutes
            if (timeUntilExpiry < 5 * 60 * 1000) {
                showToast('Attention', 'Votre session expire bientôt', 'warning');
            }
        }

        showPage('dashboard');
        initializeSocket();
        startLatencyMonitoring();
    } catch (error) {
        console.error('Erreur de vérification d\'authentification:', error);
        handleSessionExpired();
    }
}

async function handleLogin(event) {
    event.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    try {
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password }),
            credentials: 'include'
        });

        if (!response.ok) {
            throw new Error('Erreur de connexion');
        }

        const data = await response.json();
        if (data.token) {
            // Stocker le token
            localStorage.setItem('token', data.token);
            currentUser = data;
            showPage('dashboard');
            initializeSocket();
            startLatencyMonitoring();
            showToast('Connexion', 'Connexion réussie', 'success');
        } else {
            showToast('Erreur de connexion', 'Réponse invalide du serveur', 'danger');
        }
    } catch (error) {
        console.error('Erreur de connexion:', error);
        showToast('Erreur', 'Impossible de se connecter au serveur', 'danger');
    }
}

async function handleLogout() {
    try {
        // Déconnecter le socket avant la déconnexion
        if (socket) {
            socket.disconnect();
            socket = null;
        }

        // Appeler l'API de déconnexion
        const response = await fetch('/api/auth/logout', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'include'
        });

        if (!response.ok) {
            throw new Error('Erreur lors de la déconnexion');
        }

        // Réinitialiser l'état de l'application
        currentUser = null;
        localStorage.removeItem('token');

        // Supprimer les cookies de session
        document.cookie.split(";").forEach(function (c) {
            document.cookie = c.replace(/^ +/, "").replace(/=.*/, "=;expires=" + new Date().toUTCString() + ";path=/");
        });

        // Rediriger vers la page de connexion
        showPage('login');

        // Réinitialiser le formulaire de connexion
        const loginForm = document.getElementById('loginForm');
        if (loginForm) {
            loginForm.reset();
        }

        showToast('Déconnexion', 'Vous avez été déconnecté avec succès', 'success');
    } catch (error) {
        console.error('Erreur de déconnexion:', error);
        showToast('Erreur', 'Impossible de se déconnecter', 'danger');
    }
}

// Navigation
function handleNavigation(event) {
    event.preventDefault();
    const page = event.currentTarget.getAttribute('href').substring(1);

    // Vérifier si l'utilisateur est connecté pour les pages protégées
    if (page !== 'login' && !currentUser) {
        showToast('Session expirée', 'Veuillez vous reconnecter', 'warning');
        showPage('login');
        return;
    }

    showPage(page);
}

function showPage(pageId) {
    console.log('Affichage de la page:', pageId);

    // Cacher toutes les pages
    document.querySelectorAll('.page').forEach(page => {
        page.classList.add('d-none');
    });

    // Afficher la page demandée
    const page = document.getElementById(pageId);
    if (page) {
        page.classList.remove('d-none');

        // Mettre à jour la navigation active
        document.querySelectorAll('.nav-link').forEach(link => {
            if (link.getAttribute('href') === `#${pageId}`) {
                link.classList.add('active');
            } else {
                link.classList.remove('active');
            }
        });

        // Charger les données spécifiques à la page
        switch (pageId) {
            case 'devices':
                loadDevices();
                break;
            case 'dashboard':
                loadDashboardData();
                break;
            case 'alerts':
                loadAlerts();
                break;
            case 'reports':
                // Réinitialiser le formulaire de rapport
                const reportForm = document.getElementById('reportForm');
                if (reportForm) {
                    reportForm.reset();
                }
                break;
        }
    } else {
        console.error(`Page ${pageId} non trouvée`);
    }
}

// Gestion du tableau de bord
async function loadDashboardData() {
    try {
        if (!currentUser) {
            showToast('Session expirée', 'Veuillez vous reconnecter', 'warning');
            showPage('login');
            return;
        }

        const data = await apiRequest('/api/metrics/latency');
        updateLatencyChart(data);

        // Réinitialiser les valeurs du test de vitesse
        const downloadSpeed = document.getElementById('downloadSpeed');
        const uploadSpeed = document.getElementById('uploadSpeed');
        if (downloadSpeed) downloadSpeed.textContent = '-- Mbps';
        if (uploadSpeed) uploadSpeed.textContent = '-- Mbps';
    } catch (error) {
        console.error('Erreur lors du chargement des données du tableau de bord:', error);
        showToast('Erreur', 'Impossible de charger les données du tableau de bord', 'danger');
    }
}

// Gestion des appareils
async function loadDevices() {
    try {
        // Vérifier si l'utilisateur est connecté
        if (!currentUser) {
            showToast('Session expirée', 'Veuillez vous reconnecter', 'warning');
            showPage('login');
            return;
        }

        const token = localStorage.getItem('token');
        if (!token) {
            handleSessionExpired();
            return;
        }

        const response = await fetch('/api/network/devices', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            credentials: 'include'
        });

        if (response.status === 401) {
            handleSessionExpired();
            return;
        }

        if (!response.ok) {
            throw new Error('Erreur lors de la récupération des appareils');
        }

        const data = await response.json();
        updateDevicesList(data.devices || []);
    } catch (error) {
        console.error('Erreur lors du chargement des appareils:', error);
        showToast('Erreur', 'Impossible de charger la liste des appareils', 'danger');
    }
}

function updateDevicesList(devices) {
    const devicesList = document.getElementById('devicesList');
    if (!devicesList) {
        console.error('Liste des appareils non trouvée');
        return;
    }

    devicesList.innerHTML = '';
    devices.forEach(device => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${device.ip}</td>
            <td>${device.mac || 'N/A'}</td>
            <td>${device.hostname || 'N/A'}</td>
            <td>${device.vendor || 'N/A'}</td>
            <td>
                <span class="badge ${device.status === 'online' ? 'bg-success' : 'bg-danger'}">
                    ${device.status}
                </span>
            </td>
            <td>${device.latency ? device.latency + ' ms' : 'N/A'}</td>
            <td>${device.lastSeen ? new Date(device.lastSeen).toLocaleString() : 'N/A'}</td>
            <td>
                <button class="btn btn-sm btn-primary" onclick="pingDevice('${device.ip}')">
                    <i class="bi bi-arrow-repeat"></i>
                </button>
                <button class="btn btn-sm btn-info" onclick="monitorDevice('${device.ip}')">
                    <i class="bi bi-graph-up"></i>
                </button>
            </td>
        `;
        devicesList.appendChild(row);
    });
}

async function scanNetwork() {
    const button = document.getElementById('scanNetworkBtn');
    if (!button) return;

    button.disabled = true;
    button.innerHTML = '<i class="bi bi-hourglass-split"></i> Scan en cours...';

    try {
        const data = await apiRequest('/api/network/scan', {
            method: 'POST'
        });

        if (data.success) {
            showToast('Succès', 'Scan du réseau terminé', 'success');
            loadDevices();
        } else {
            showToast('Erreur', data.message || 'Erreur lors du scan', 'danger');
        }
    } catch (error) {
        console.error('Erreur lors du scan:', error);
        showToast('Erreur', 'Impossible de scanner le réseau', 'danger');
    } finally {
        button.disabled = false;
        button.innerHTML = '<i class="bi bi-search"></i> Scanner le réseau';
    }
}

async function pingDevice(ip) {
    try {
        const response = await fetch(`/api/network/ping/${ip}`, {
            credentials: 'include'
        });

        if (!response.ok) {
            throw new Error('Erreur lors du ping');
        }

        const data = await response.json();
        if (data.success) {
            showToast('Succès', `Latence: ${data.latency}ms`, 'success');
            loadDevices();
        } else {
            showToast('Erreur', data.message || 'Erreur lors du ping', 'danger');
        }
    } catch (error) {
        console.error('Erreur lors du ping:', error);
        showToast('Erreur', 'Impossible de pinger l\'appareil', 'danger');
    }
}

// Gestion des graphiques
function initializeCharts() {
    const latencyCtx = document.getElementById('latencyChart');
    if (!latencyCtx) {
        console.error('Canvas du graphique de latence non trouvé');
        return;
    }

    latencyChart = new Chart(latencyCtx.getContext('2d'), {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Latence (ms)',
                data: [],
                borderColor: 'rgb(75, 192, 192)',
                tension: 0.1
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

function updateLatencyChart(data) {
    if (!latencyChart) {
        console.error('Graphique de latence non initialisé');
        return;
    }

    latencyChart.data.labels = data.map(d => new Date(d.timestamp).toLocaleTimeString());
    latencyChart.data.datasets[0].data = data.map(d => d.latency);
    latencyChart.update();
}

// Monitoring de la latence
function startLatencyMonitoring() {
    // Vérifier si l'utilisateur est connecté
    if (!currentUser) {
        console.log('Utilisateur non connecté, arrêt du monitoring');
        return;
    }

    setInterval(async () => {
        try {
            // Vérifier si l'utilisateur est toujours connecté
            if (!currentUser) {
                console.log('Utilisateur déconnecté, arrêt du monitoring');
                return;
            }

            const response = await fetch('/api/metrics/latency', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json'
                },
                credentials: 'include'
            });

            if (response.status === 401) {
                console.log('Session expirée, arrêt du monitoring');
                currentUser = null;
                showPage('login');
                return;
            }

            if (!response.ok) {
                throw new Error('Erreur lors de la récupération de la latence');
            }

            const data = await response.json();
            updateLatencyChart(data);
        } catch (error) {
            console.error('Erreur lors de la récupération de la latence:', error);
        }
    }, 60000); // Mise à jour toutes les minutes

    // Mise à jour immédiate
    loadDashboardData();
}

// Test de vitesse
async function startSpeedTest() {
    const button = document.getElementById('startSpeedTest');
    if (!button) return;

    button.disabled = true;
    button.textContent = 'Test en cours...';

    try {
        // Test de téléchargement
        const downloadData = await apiRequest('/api/network/speed-test/download', {
            method: 'GET'
        });

        // Test d'upload
        const uploadData = await apiRequest('/api/network/speed-test/upload', {
            method: 'POST'
        });

        const downloadSpeed = document.getElementById('downloadSpeed');
        const uploadSpeed = document.getElementById('uploadSpeed');

        if (downloadSpeed) {
            downloadSpeed.textContent = `${downloadData.speed.toFixed(2)} Mbps`;
        }
        if (uploadSpeed) {
            uploadSpeed.textContent = `${uploadData.speed.toFixed(2)} Mbps`;
        }

        showToast('Succès', 'Test de vitesse terminé', 'success');
    } catch (error) {
        console.error('Erreur lors du test de vitesse:', error);
        showToast('Erreur', 'Impossible d\'effectuer le test de vitesse', 'danger');
    } finally {
        button.disabled = false;
        button.textContent = 'Lancer le test';
    }
}

// Gestion des alertes
async function loadAlerts() {
    try {
        const alerts = await apiRequest('/api/alerts');
        const alertsList = document.getElementById('alertsList');
        if (!alertsList) return;

        alertsList.innerHTML = '';
        alerts.forEach(alert => {
            const alertElement = document.createElement('div');
            alertElement.className = 'alert alert-warning alert-dismissible fade show';
            alertElement.innerHTML = `
                <strong>${alert.type}</strong> - ${alert.message}
                <small class="text-muted d-block">${new Date(alert.timestamp).toLocaleString()}</small>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            `;
            alertsList.appendChild(alertElement);
        });
    } catch (error) {
        console.error('Erreur lors du chargement des alertes:', error);
        showToast('Erreur', 'Impossible de charger les alertes', 'danger');
    }
}

// Gestion des rapports
async function generateReport(event) {
    event.preventDefault();
    const startDate = document.getElementById('startDate').value;
    const endDate = document.getElementById('endDate').value;

    try {
        const data = await apiRequest('/api/reports/generate', {
            method: 'POST',
            body: JSON.stringify({ startDate, endDate })
        });

        if (data.success) {
            const reportContent = document.getElementById('reportContent');
            if (reportContent) {
                reportContent.innerHTML = data.html;
            }
            showToast('Succès', 'Rapport généré avec succès', 'success');
        } else {
            showToast('Erreur', data.message || 'Erreur lors de la génération du rapport', 'danger');
        }
    } catch (error) {
        console.error('Erreur lors de la génération du rapport:', error);
        showToast('Erreur', 'Impossible de générer le rapport', 'danger');
    }
}

// Gestion des notifications
function showToast(title, message, type = 'info') {
    const toastContainer = document.querySelector('.toast-container');
    if (!toastContainer) {
        console.error('Conteneur de notifications non trouvé');
        return;
    }

    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-white bg-${type} border-0`;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');

    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                <strong>${title}</strong><br>
                ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;

    toastContainer.appendChild(toast);
    const bsToast = new bootstrap.Toast(toast);
    bsToast.show();

    toast.addEventListener('hidden.bs.toast', () => {
        toast.remove();
    });
}

// Initialisation de Socket.IO
function initializeSocket() {
    socket = io({
        auth: {
            token: document.cookie.split('; ').find(row => row.startsWith('token='))?.split('=')[1]
        }
    });

    socket.on('connect', () => {
        console.log('Connecté au serveur WebSocket');
    });

    socket.on('disconnect', () => {
        console.log('Déconnecté du serveur WebSocket');
    });

    socket.on('deviceUpdate', (device) => {
        loadDevices();
    });

    socket.on('alert', (alert) => {
        showToast('Alerte', alert.message, 'warning');
    });
}

// Gestion de la session expirée
function handleSessionExpired() {
    // Déconnecter le socket
    if (socket) {
        socket.disconnect();
        socket = null;
    }

    // Nettoyer les données de session
    localStorage.removeItem('token');
    currentUser = null;

    // Afficher le toast
    const toast = new bootstrap.Toast(document.getElementById('sessionExpiredToast'));
    toast.show();

    // Rediriger vers la page de connexion
    showPage('login');

    // Réinitialiser le formulaire de connexion
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.reset();
    }
}

// Écouter les événements de session expirée du serveur
socket.on('session:expired', () => {
    handleSessionExpired();
});

// Vérification périodique de la session
function startSessionCheck() {
    setInterval(async () => {
        if (currentUser) {
            try {
                const response = await fetch('/api/auth/check', {
                    method: 'GET',
                    credentials: 'include'
                });

                if (!response.ok) {
                    handleSessionExpired();
                }
            } catch (error) {
                console.error('Erreur de vérification de session:', error);
                handleSessionExpired();
            }
        }
    }, 60000); // Vérifier toutes les minutes
}

// Fonction utilitaire pour les requêtes API
async function apiRequest(url, options = {}) {
    const token = localStorage.getItem('token');
    if (!token) {
        handleSessionExpired();
        throw new Error('Non authentifié');
    }

    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        credentials: 'include'
    };

    const response = await fetch(url, { ...defaultOptions, ...options });

    if (response.status === 401) {
        handleSessionExpired();
        throw new Error('Session expirée');
    }

    if (!response.ok) {
        throw new Error(`Erreur API: ${response.statusText}`);
    }

    return response.json();
} 