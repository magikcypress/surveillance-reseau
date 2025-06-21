// Variables globales
let currentUser = null;
let socket = null;
let socketInitialized = false;
let latencyChart = null;

// Fonction pour vérifier si l'utilisateur est authentifié
function isAuthenticated() {
    return localStorage.getItem('accessToken') !== null;
}

// Fonction pour rediriger vers la page de connexion si non authentifié
function checkAuth() {
    if (!isAuthenticated() && window.location.pathname !== '/index.html' && window.location.pathname !== '/register.html') {
        window.location.href = '/index.html';
    }
}

// Fonction pour vérifier si Socket.IO est initialisé
function isSocketInitialized() {
    return socketInitialized && socket && socket.connected;
}

// Fonction pour réinitialiser Socket.IO
function resetSocket() {
    if (socket) {
        socket.disconnect();
        socket = null;
    }
    socketInitialized = false;
}

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
});

// Configuration des événements
function setupEventListeners() {
    console.log('Configuration des événements...');

    // Formulaire de connexion
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLoginSubmit);
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

    // Formulaire d'inscription
    const registerForm = document.getElementById('register-form');
    if (registerForm) {
        registerForm.addEventListener('submit', handleRegisterSubmit);
    }
}

// Fonction pour vérifier l'authentification
async function checkAuth() {
    try {
        const accessToken = localStorage.getItem('accessToken');
        if (!accessToken) {
            showPage('login');
            return;
        }

        // Vérifier le token
        const response = await fetch('/api/auth/verify', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${accessToken}`
            }
        });

        if (!response.ok) {
            // Essayer de rafraîchir le token
            const refreshResult = await refreshAccessToken();
            if (!refreshResult) {
                handleSessionExpired();
                return;
            }
        }

        const data = await response.json();
        if (data.success) {
            currentUser = data.data.user;
            showPage('dashboard');
            initializeSocket();
        } else {
            handleSessionExpired();
        }
    } catch (error) {
        console.error('Erreur de vérification d\'authentification:', error);
        handleSessionExpired();
    }
}

// Fonction pour rafraîchir le token d'accès
async function refreshAccessToken() {
    try {
        const refreshToken = localStorage.getItem('refreshToken');
        if (!refreshToken) {
            return false;
        }

        const response = await fetch('/api/auth/refresh', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ refreshToken })
        });

        if (!response.ok) {
            return false;
        }

        const data = await response.json();
        if (data.success) {
            localStorage.setItem('accessToken', data.data.accessToken);
            localStorage.setItem('refreshToken', data.data.refreshToken);
            localStorage.setItem('user', JSON.stringify(data.data.user));
            return true;
        }

        return false;
    } catch (error) {
        console.error('Erreur lors du rafraîchissement du token:', error);
        return false;
    }
}

// Fonction de connexion
async function login(username, password) {
    try {
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || 'Erreur de connexion');
        }

        if (!data.success) {
            throw new Error(data.message || 'Erreur de connexion');
        }

        // Stocker les tokens dans le localStorage
        localStorage.setItem('accessToken', data.data.accessToken);
        localStorage.setItem('refreshToken', data.data.refreshToken);

        // Stocker les informations de l'utilisateur
        localStorage.setItem('user', JSON.stringify(data.data.user));
        currentUser = data.data.user;

        // Initialiser la connexion socket
        initializeSocket();

        // Vérifier le rôle et afficher les éléments appropriés
        checkUserRole();

        // Afficher la page dashboard directement
        showPage('dashboard');

        // Afficher un message de succès
        showToast('Succès', 'Connexion réussie', 'success');
    } catch (error) {
        console.error('Login error:', error);
        showError('Erreur de connexion: ' + error.message);
    }
}

// Fonction pour gérer la soumission du formulaire de connexion
function handleLoginSubmit(event) {
    event.preventDefault();

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    if (!username || !password) {
        showError('Veuillez remplir tous les champs');
        return;
    }

    login(username, password);
}

// Fonction pour afficher les erreurs
function showError(message) {
    const errorElement = document.getElementById('error-message');
    if (errorElement) {
        errorElement.textContent = message;
        errorElement.style.display = 'block';
    } else {
        alert(message);
    }
}

// Fonction d'inscription
async function register(username, password, confirmPassword) {
    try {
        // Validation des données
        if (!username || !password || !confirmPassword) {
            throw new Error('Veuillez remplir tous les champs');
        }

        if (username.length < 3) {
            throw new Error('Le nom d\'utilisateur doit contenir au moins 3 caractères');
        }

        if (password.length < 8) {
            throw new Error('Le mot de passe doit contenir au moins 8 caractères');
        }

        if (password !== confirmPassword) {
            throw new Error('Les mots de passe ne correspondent pas');
        }

        const response = await fetch('/api/auth/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({
                username: username.trim(),
                password: password,
                confirmPassword: confirmPassword
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || 'Erreur lors de l\'inscription');
        }

        if (!data.success) {
            throw new Error(data.message || 'Erreur lors de l\'inscription');
        }

        // Stocker les tokens dans le localStorage
        localStorage.setItem('accessToken', data.data.accessToken);
        localStorage.setItem('refreshToken', data.data.refreshToken);

        // Stocker les informations de l'utilisateur
        localStorage.setItem('user', JSON.stringify(data.data.user));
        currentUser = data.data.user;

        // Initialiser la connexion socket
        initializeSocket();

        // Afficher la page dashboard directement
        showPage('dashboard');

        // Afficher un message de succès
        showToast('Succès', 'Inscription réussie', 'success');
    } catch (error) {
        console.error('Registration error:', error);
        showError(error.message || 'Erreur lors de l\'inscription');
    }
}

// Fonction pour gérer la soumission du formulaire d'inscription
function handleRegisterSubmit(event) {
    event.preventDefault();

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirm-password').value;

    // Validation des champs
    if (!username || !password || !confirmPassword) {
        showError('Veuillez remplir tous les champs');
        return;
    }

    if (username.length < 3) {
        showError('Le nom d\'utilisateur doit contenir au moins 3 caractères');
        return;
    }

    if (password.length < 8) {
        showError('Le mot de passe doit contenir au moins 8 caractères');
        return;
    }

    if (password !== confirmPassword) {
        showError('Les mots de passe ne correspondent pas');
        return;
    }

    // Nettoyage des espaces
    const cleanUsername = username.trim();
    if (cleanUsername.length < 3) {
        showError('Le nom d\'utilisateur ne peut pas être composé uniquement d\'espaces');
        return;
    }

    register(cleanUsername, password, confirmPassword);
}

// Fonction de déconnexion
async function logout() {
    try {
        await apiRequest('/api/auth/logout', {
            method: 'POST'
        });

        if (socket) {
            socket.disconnect();
        }

        localStorage.removeItem('accessToken');
        localStorage.removeItem('refreshToken');
        localStorage.removeItem('user');
        currentUser = null;
        showPage('login');
        showToast('Succès', 'Déconnexion réussie', 'success');
    } catch (error) {
        console.error('Erreur lors de la déconnexion:', error);
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
            case 'admin':
                loadUsers();
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
        const response = await apiRequest('/api/alerts');
        const data = await response.json();

        if (data.alerts && data.alerts.length > 0) {
            const alertsList = document.getElementById('alertsList');
            alertsList.innerHTML = data.alerts.map(alert => `
                <div class="alert alert-${alert.resolved ? 'success' : 'warning'} d-flex justify-content-between align-items-center">
                    <div>
                        <strong>${alert.type}</strong>: ${alert.message}
                        <br><small>${new Date(alert.timestamp).toLocaleString()}</small>
                    </div>
                    ${!alert.resolved ? `
                        <button class="btn btn-sm btn-success" onclick="resolveAlert(${alert.id})">
                            Résoudre
                        </button>
                    ` : ''}
                </div>
            `).join('');
        } else {
            document.getElementById('alertsList').innerHTML = '<p class="text-muted">Aucune alerte pour le moment.</p>';
        }
    } catch (error) {
        console.error('Erreur lors du chargement des alertes:', error);
        showToast('Erreur', 'Impossible de charger les alertes', 'danger');
    }
}

// Gestion des utilisateurs (administration)
async function loadUsers() {
    try {
        const response = await apiRequest('/api/auth/users');
        const data = await response.json();

        if (data.success && data.data.users) {
            updateUsersList(data.data.users);
        } else {
            showToast('Erreur', data.message || 'Impossible de charger les utilisateurs', 'danger');
        }
    } catch (error) {
        console.error('Erreur lors du chargement des utilisateurs:', error);
        showToast('Erreur', 'Impossible de charger les utilisateurs', 'danger');
    }
}

function updateUsersList(users) {
    const usersList = document.getElementById('usersList');
    if (!usersList) return;

    usersList.innerHTML = users.map(user => `
        <tr>
            <td>${user.id}</td>
            <td>${user.username}</td>
            <td>${user.email}</td>
            <td>
                <span class="badge bg-${user.role === 'admin' ? 'danger' : 'primary'}">${user.role}</span>
            </td>
            <td>${user.last_login ? new Date(user.last_login).toLocaleString() : 'Jamais'}</td>
            <td>
                <span class="badge bg-${user.is_active ? 'success' : 'secondary'}">
                    ${user.is_active ? 'Actif' : 'Inactif'}
                </span>
            </td>
            <td>
                ${user.id !== currentUser.id ? `
                    <button class="btn btn-sm btn-danger" onclick="deleteUser(${user.id}, '${user.username}')">
                        <i class="bi bi-trash"></i> Supprimer
                    </button>
                ` : '<span class="text-muted">Vous</span>'}
            </td>
        </tr>
    `).join('');
}

async function deleteUser(userId, username) {
    if (!confirm(`Êtes-vous sûr de vouloir supprimer l'utilisateur "${username}" ? Cette action est irréversible.`)) {
        return;
    }

    try {
        const response = await apiRequest(`/api/auth/users/${userId}`, {
            method: 'DELETE'
        });

        const data = await response.json();

        if (data.success) {
            showToast('Succès', 'Utilisateur supprimé avec succès', 'success');
            loadUsers(); // Recharger la liste
        } else {
            showToast('Erreur', data.message || 'Erreur lors de la suppression', 'danger');
        }
    } catch (error) {
        console.error('Erreur lors de la suppression de l\'utilisateur:', error);
        showToast('Erreur', 'Impossible de supprimer l\'utilisateur', 'danger');
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

// Fonction pour initialiser Socket.IO
function initializeSocket() {
    try {
        // Vérifier si l'utilisateur est authentifié
        const accessToken = localStorage.getItem('accessToken');
        if (!accessToken) {
            console.log('Utilisateur non authentifié, Socket.IO non initialisé');
            return;
        }

        // Vérifier si Socket.IO est déjà initialisé
        if (socket && socket.connected) {
            console.log('Socket.IO déjà connecté');
            return;
        }

        console.log('Initialisation de Socket.IO...');

        // Initialiser Socket.IO avec le token d'authentification
        socket = io({
            auth: {
                token: accessToken
            }
        });

        socket.on('connect', () => {
            console.log('Connected to server');
            socketInitialized = true;
        });

        socket.on('disconnect', () => {
            console.log('Disconnected from server');
            socket = null;
            socketInitialized = false;
        });

        socket.on('error', (error) => {
            console.error('Socket error:', error);
            showError('Erreur de connexion au serveur');
            resetSocket();
        });

        socket.on('deviceUpdate', (data) => {
            if (isSocketInitialized()) {
                updateDeviceStatus(data);
            }
        });

        socket.on('metricUpdate', (data) => {
            if (isSocketInitialized()) {
                updateMetrics(data);
            }
        });

        socket.on('connect_error', (error) => {
            console.error('Socket connection error:', error);
            if (error.message === 'Authentication failed') {
                localStorage.removeItem('accessToken');
                localStorage.removeItem('refreshToken');
                localStorage.removeItem('user');
                handleSessionExpired();
            }
            resetSocket();
        });

    } catch (error) {
        console.error('Error initializing socket:', error);
        showError('Erreur de connexion au serveur');
        resetSocket();
    }
}

// Fonction pour mettre à jour le statut d'un appareil
function updateDeviceStatus(data) {
    if (!data || !data.id) {
        console.error('Invalid device update data:', data);
        return;
    }

    const deviceElement = document.querySelector(`[data-device-id="${data.id}"]`);
    if (deviceElement) {
        const statusElement = deviceElement.querySelector('.device-status');
        const lastSeenElement = deviceElement.querySelector('.device-last-seen');

        if (statusElement) {
            statusElement.textContent = data.status;
        }
        if (lastSeenElement) {
            lastSeenElement.textContent = new Date(data.lastSeen).toLocaleString();
        }
    }
}

// Fonction pour mettre à jour les métriques
function updateMetrics(data) {
    if (!data || !data.deviceId) {
        console.error('Invalid metrics update data:', data);
        return;
    }

    const metricsElement = document.querySelector(`[data-device-id="${data.deviceId}"] .device-metrics`);
    if (metricsElement) {
        metricsElement.innerHTML = `
            <div>Latence: ${data.latency}ms</div>
            <div>Paquets perdus: ${data.packetLoss}%</div>
        `;
    }
}

// Gestion de la session expirée
function handleSessionExpired() {
    if (socket) {
        socket.disconnect();
    }

    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    localStorage.removeItem('user');
    currentUser = null;

    const toast = document.getElementById('sessionExpiredToast');
    if (toast) {
        const bsToast = new bootstrap.Toast(toast);
        bsToast.show();
    }

    showPage('login');
}

// Fonction utilitaire pour les requêtes API
async function apiRequest(url, options = {}) {
    try {
        const accessToken = localStorage.getItem('accessToken');

        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
                ...(accessToken && { 'Authorization': `Bearer ${accessToken}` }),
                ...options.headers
            }
        };

        const response = await fetch(url, { ...defaultOptions, ...options });

        // Si le token a expiré, essayer de le rafraîchir
        if (response.status === 401) {
            const refreshResult = await refreshAccessToken();
            if (refreshResult) {
                // Réessayer la requête avec le nouveau token
                const newAccessToken = localStorage.getItem('accessToken');
                const newOptions = {
                    ...options,
                    headers: {
                        ...options.headers,
                        'Authorization': `Bearer ${newAccessToken}`
                    }
                };
                return await fetch(url, { ...defaultOptions, ...newOptions });
            } else {
                handleSessionExpired();
                throw new Error('Session expirée');
            }
        }

        return response;
    } catch (error) {
        console.error('Erreur lors de la requête API:', error);
        throw error;
    }
}

// Initialisation de l'application
async function initializeApp() {
    try {
        // Configurer les événements en premier
        setupEventListeners();

        // Récupérer l'utilisateur depuis le localStorage s'il existe
        const userStr = localStorage.getItem('user');
        if (userStr) {
            try {
                currentUser = JSON.parse(userStr);
            } catch (error) {
                console.error('Erreur lors du parsing de l\'utilisateur:', error);
                localStorage.removeItem('user');
            }
        }

        // Vérifier l'authentification seulement si pas déjà connecté
        if (!currentUser) {
            const accessToken = localStorage.getItem('accessToken');
            if (accessToken) {
                await checkAuth();
            } else {
                showPage('login');
            }
        } else {
            // Si l'utilisateur est déjà connecté, afficher le dashboard
            showPage('dashboard');
            initializeSocket();
        }

    } catch (error) {
        console.error('Erreur lors de l\'initialisation:', error);
        showToast('Erreur', 'Impossible d\'initialiser l\'application', 'danger');
        showPage('login');
    }
}

// Fonction pour envoyer un message via Socket.IO
function emitSocketEvent(event, data) {
    if (socket && socket.connected) {
        socket.emit(event, data);
    } else {
        console.warn('Socket non connecté, tentative de reconnexion...');
        initializeSocket();
    }
}

// Fonction pour gérer la déconnexion
async function handleLogout() {
    try {
        await apiRequest('/api/auth/logout', {
            method: 'POST'
        });

        if (socket) {
            socket.disconnect();
        }

        localStorage.removeItem('accessToken');
        localStorage.removeItem('refreshToken');
        localStorage.removeItem('user');
        currentUser = null;
        showPage('login');
        showToast('Succès', 'Déconnexion réussie', 'success');
    } catch (error) {
        console.error('Erreur lors de la déconnexion:', error);
        showToast('Erreur', 'Impossible de se déconnecter', 'danger');
    }
}

// Démarrer l'application
document.addEventListener('DOMContentLoaded', initializeApp);

function checkUserRole() {
    if (currentUser && currentUser.role === 'admin') {
        // Afficher les éléments d'administration
        const adminNavItem = document.getElementById('adminNavItem');
        if (adminNavItem) {
            adminNavItem.style.display = 'block';
        }
    }
} 