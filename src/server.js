const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const session = require('express-session');
const path = require('path');
const auth = require('./auth');
const db = require('./database');
const NetworkMonitor = require('./network-monitor');
const SpeedTest = require('./speed-test');
const Notifier = require('./notifier');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Configuration de la session
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000 // 24 heures
    }
}));

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Routes d'authentification
app.post('/api/auth/register', async (req, res) => {
    try {
        const result = await auth.register(req.body);
        res.json(result);
    } catch (error) {
        console.error('Registration error:', error);
        res.status(400).json({
            error: error.message,
            code: 'REGISTRATION_ERROR'
        });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const result = await auth.login(req.body);
        res.json(result);
    } catch (error) {
        console.error('Login error:', error);
        res.status(401).json({
            error: error.message,
            code: 'LOGIN_ERROR'
        });
    }
});

app.post('/api/auth/logout', auth.authenticate.bind(auth), async (req, res) => {
    try {
        await auth.logout(req, res);
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({
            error: error.message,
            code: 'LOGOUT_ERROR'
        });
    }
});

// Routes protégées
app.get('/api/network/devices', auth.authenticate.bind(auth), async (req, res) => {
    try {
        const devices = await db.getDevices();
        res.json(devices);
    } catch (error) {
        console.error('Error fetching devices:', error);
        res.status(500).json({
            error: 'Failed to fetch devices',
            code: 'FETCH_DEVICES_ERROR'
        });
    }
});

app.post('/api/network/scan', auth.authenticate.bind(auth), async (req, res) => {
    try {
        const networkMonitor = new NetworkMonitor();
        const result = await networkMonitor.scanNetwork();
        res.json(result);
    } catch (error) {
        console.error('Network scan error:', error);
        res.status(500).json({
            error: 'Network scan failed',
            code: 'SCAN_ERROR'
        });
    }
});

app.post('/api/network/speed-test', auth.authenticate.bind(auth), async (req, res) => {
    try {
        const speedTest = new SpeedTest();
        const result = await speedTest.runSpeedTest();
        res.json(result);
    } catch (error) {
        console.error('Speed test error:', error);
        res.status(500).json({
            error: 'Speed test failed',
            code: 'SPEED_TEST_ERROR'
        });
    }
});

// Gestion des erreurs globale
app.use((err, req, res, next) => {
    console.error('Global error handler:', err);
    res.status(500).json({
        error: 'Internal server error',
        code: 'SERVER_ERROR'
    });
});

// Configuration de Socket.IO
io.on('connection', (socket) => {
    console.log('Client connected');

    socket.on('disconnect', () => {
        console.log('Client disconnected');
    });
});

// Démarrage du serveur
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
}); 