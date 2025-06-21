const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const ping = require('ping');
const NetworkMonitor = require('./network-monitor');
const SpeedTest = require('./speed-test');
const auth = require('./auth');
const notifier = require('./notifier');
const Database = require('./database');
const ErrorHandler = require('./utils/errorHandler');
const authRoutes = require('./routes/authRoutes');
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

const app = express();
const server = http.createServer(app);
const io = socketIo(server);
const networkMonitor = new NetworkMonitor();
const speedTest = new SpeedTest();
const db = new Database();

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Configuration de la session
app.use(session({
    store: new SQLiteStore({
        db: 'sessions.db',
        dir: path.join(__dirname, 'data')
    }),
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000 // 24 heures
    }
}));

// Routes d'authentification
app.use('/api/auth', authRoutes);

// Middleware de gestion des erreurs
app.use(ErrorHandler.handle);

// Routes API
app.get('/api/network/devices', auth.authenticate, async (req, res) => {
    try {
        const devices = await db.getDevices();
        res.json({ devices });
    } catch (error) {
        console.error('Erreur lors de la récupération des appareils:', error);
        res.status(500).json({ error: 'Erreur lors de la récupération des appareils' });
    }
});

app.get('/api/metrics/:deviceId', auth.authenticate, async (req, res) => {
    try {
        const { deviceId } = req.params;
        const { startDate, endDate } = req.query;
        const metrics = await db.getMetrics(deviceId, startDate, endDate);
        res.json(metrics);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.get('/api/alerts', async (req, res) => {
    try {
        const alerts = await db.getAlerts();
        res.json({ alerts });
    } catch (error) {
        console.error('Erreur lors de la récupération des alertes:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.post('/api/alerts/:alertId/resolve', auth.authenticate, async (req, res) => {
    try {
        const { alertId } = req.params;
        await db.resolveAlert(alertId);
        res.json({ message: 'Alerte résolue' });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.post('/api/reports/generate', async (req, res) => {
    try {
        const { startDate, endDate } = req.body;
        if (!startDate || !endDate) {
            return res.status(400).json({ error: 'Dates requises' });
        }

        const report = await db.generateReport(startDate, endDate);
        res.json(report);
    } catch (error) {
        console.error('Erreur lors de la génération du rapport:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// Route pour scanner le réseau
app.post('/api/network/scan', auth.authenticate, async (req, res) => {
    try {
        console.log('Démarrage du scan réseau...');
        const network = '192.168.1.0/24';
        const activeIPs = new Set();

        // Supprimer tous les appareils existants
        await db.clearDevices();

        // Scanner le réseau
        for (let i = 1; i < 255; i++) {
            const ip = `192.168.1.${i}`;
            try {
                const result = await ping.promise.probe(ip, {
                    timeout: 1,
                    extra: ['-c', '1']
                });

                if (result.alive) {
                    console.log(`Appareil trouvé: ${ip}`);
                    let hostname = 'Inconnu';
                    let mac = 'Inconnu';
                    let vendor = 'Inconnu';

                    // Récupérer les informations avec nmap
                    try {
                        // Commande pour obtenir l'adresse MAC et le nom d'hôte
                        const { stdout: nmapOutput } = await execAsync(`nmap -sn -PR -n --system-dns ${ip}`);
                        if (nmapOutput) {
                            // Extraire l'adresse MAC
                            const macMatch = nmapOutput.toString().match(/MAC Address: ([0-9A-Fa-f:]+)/);
                            if (macMatch) {
                                mac = macMatch[1];
                            }

                            // Extraire le nom d'hôte
                            const hostnameMatch = nmapOutput.toString().match(/Host is up.*?\((.*?)\)/);
                            if (hostnameMatch) {
                                hostname = hostnameMatch[1];
                            }
                        }

                        // Commande séparée pour obtenir le fabricant
                        if (mac !== 'Inconnu') {
                            const { stdout: vendorOutput } = await execAsync(`nmap -sV --version-intensity 0 -n ${ip}`);
                            if (vendorOutput) {
                                const vendorMatch = vendorOutput.toString().match(/MAC Address: [0-9A-Fa-f:]+ \((.+?)\)/);
                                if (vendorMatch) {
                                    vendor = vendorMatch[1].trim();
                                }
                            }
                        }

                        // Scanner les ports ouverts
                        const { stdout: portsOutput } = await execAsync(`nmap -sS -F -n ${ip}`);
                        let openPorts = [];
                        if (portsOutput) {
                            const portMatches = portsOutput.toString().matchAll(/(\d+)\/tcp\s+open\s+(\w+)/g);
                            for (const match of portMatches) {
                                openPorts.push({
                                    port: match[1],
                                    service: match[2]
                                });
                            }
                        }

                        activeIPs.add({
                            ip,
                            hostname,
                            mac,
                            vendor,
                            status: 'online',
                            latency: result.time,
                            lastSeen: new Date().toISOString(),
                            openPorts
                        });
                    } catch (error) {
                        console.log(`Erreur lors de la récupération des informations pour ${ip}:`, error.message);
                    }
                }
            } catch (error) {
                console.log(`Erreur lors du ping de ${ip}:`, error.message);
            }
        }

        // Convertir le Set en tableau
        const devices = Array.from(activeIPs);

        // Sauvegarder les nouveaux appareils dans la base de données
        await db.saveDevices(devices);

        console.log('Scan réseau terminé');
        res.json(devices);
    } catch (error) {
        console.error('Erreur lors du scan réseau:', error);
        res.status(500).json({ error: 'Erreur lors du scan réseau' });
    }
});

app.post('/api/network/speed-test', auth.authenticate, async (req, res) => {
    try {
        const result = await speedTest.runSpeedTest();
        await db.saveSpeedTest(result);
        res.json(result);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

app.get('/api/network/speed-history', auth.authenticate, async (req, res) => {
    try {
        const { startDate, endDate } = req.query;
        const history = await db.getSpeedTestHistory(startDate, endDate);
        res.json(history);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Route pour pinger un appareil spécifique
app.get('/api/network/ping/:ip', auth.authenticate, async (req, res) => {
    try {
        const { ip } = req.params;
        const result = await ping.promise.probe(ip, {
            timeout: 1,
            extra: ['-c', '1']
        });

        if (result.alive) {
            // Mettre à jour l'appareil dans la base de données
            await db.updateDeviceStatus(ip, 'online');
            res.json({
                status: 'online',
                latency: result.time
            });
        } else {
            await db.updateDeviceStatus(ip, 'offline');
            res.json({
                status: 'offline',
                latency: null
            });
        }
    } catch (error) {
        console.error(`Erreur lors du ping de ${req.params.ip}:`, error);
        res.status(500).json({ error: 'Erreur lors du ping' });
    }
});

// Routes pour les tests de vitesse
app.get('/api/network/speed-test/download', auth.authenticate, async (req, res) => {
    try {
        console.log('Démarrage du test de téléchargement...');
        const startTime = Date.now();

        const response = await fetch('https://speed.cloudflare.com/__down?bytes=10485760', {
            method: 'GET'
        });

        const endTime = Date.now();
        const duration = (endTime - startTime) / 1000; // en secondes
        const speed = (10 * 8) / duration; // 10MB en Mbps

        console.log(`Test de téléchargement terminé: ${speed.toFixed(2)} Mbps`);
        res.json({ speed });
    } catch (error) {
        console.error('Erreur lors du test de téléchargement:', error);
        res.status(500).json({ error: 'Erreur lors du test de téléchargement' });
    }
});

app.post('/api/network/speed-test/upload', auth.authenticate, async (req, res) => {
    try {
        console.log('Démarrage du test d\'upload...');
        const startTime = Date.now();

        const response = await fetch('https://speed.cloudflare.com/__up', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/octet-stream',
                'Content-Length': '10485760' // 10MB
            },
            body: Buffer.alloc(10485760)
        });

        const endTime = Date.now();
        const duration = (endTime - startTime) / 1000; // en secondes
        const speed = (10 * 8) / duration; // 10MB en Mbps

        console.log(`Test d'upload terminé: ${speed.toFixed(2)} Mbps`);
        res.json({ speed });
    } catch (error) {
        console.error('Erreur lors du test d\'upload:', error);
        res.status(500).json({ error: 'Erreur lors du test d\'upload' });
    }
});

// Route pour mesurer la latence
app.get('/api/network/latency', auth.authenticate, async (req, res) => {
    try {
        const result = await ping.promise.probe('8.8.8.8', {
            timeout: 2,
            extra: ['-c', '1']
        });

        if (result.alive) {
            await db.saveLatencyMeasurement(result.time);
            res.json({ latency: result.time });
        } else {
            res.status(404).json({ error: 'Impossible de mesurer la latence' });
        }
    } catch (error) {
        console.error('Erreur lors de la mesure de latence:', error);
        res.status(500).json({ error: 'Erreur lors de la mesure de latence' });
    }
});

// Route pour récupérer l'historique des latences
app.get('/api/network/latency/history', auth.authenticate, async (req, res) => {
    try {
        const history = await db.getLatencyHistory();
        res.json({ history });
    } catch (error) {
        console.error('Erreur lors de la récupération de l\'historique:', error);
        res.status(500).json({ error: 'Erreur lors de la récupération de l\'historique' });
    }
});

// Route principale
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Gestion des erreurs 404
app.use((req, res) => {
    res.status(404).json({ message: 'Route non trouvée' });
});

// Configuration de Socket.IO
io.use((socket, next) => {
    const authHeader = socket.handshake.auth.token;
    if (!authHeader) {
        return next(new Error('Token manquant'));
    }

    // Extraire le token du format "Bearer <token>"
    const token = authHeader.startsWith('Bearer ')
        ? authHeader.slice(7)
        : authHeader;

    try {
        const decoded = auth.verifyToken(token);
        socket.user = decoded;
        next();
    } catch (error) {
        console.error('Erreur de vérification du token:', error);
        next(new Error('Token invalide'));
    }
});

io.on('connection', (socket) => {
    console.log('Nouveau client connecté');

    socket.on('disconnect', () => {
        console.log('Client déconnecté');
    });

    // Gestion des erreurs de test de vitesse
    socket.on('speedTestError', (error) => {
        console.error('Erreur de test de vitesse:', error);
        socket.emit('error', { message: error.message });
    });
});

// Écoute des événements de surveillance
networkMonitor.on('devices-update', (devices) => {
    io.emit('device-update', devices);
});

networkMonitor.on('metrics-update', (data) => {
    io.emit('metrics-update', data);
});

networkMonitor.on('alert', async (alert) => {
    io.emit('alert', alert);
    try {
        await notifier.sendAlert(alert);
    } catch (error) {
        console.error('Erreur lors de l\'envoi de l\'alerte:', error);
    }
});

// Démarrage du serveur
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Serveur démarré sur le port ${PORT}`);
}); 