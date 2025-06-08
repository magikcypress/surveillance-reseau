const EventEmitter = require('events');
const ping = require('ping');
const dns = require('dns').promises;
const db = require('./database');
const config = require('./config');
const notifier = require('./notifier');

class NetworkMonitor extends EventEmitter {
    constructor(io) {
        super();
        this.io = io;
        this.monitoring = false;
        this.devices = new Map();
        this.interval = null;
        this.pingInterval = 5000; // 5 secondes
        this.timeout = 2000; // 2 secondes
        this.initializeDevices();
    }

    initializeDevices() {
        // Initialiser les appareils depuis la configuration
        config.network.localNetwork.devices.forEach(device => {
            this.devices.set(device.ip, {
                ...device,
                status: 'unknown',
                lastSeen: null,
                responseTime: null
            });
        });
    }

    async startMonitoring() {
        if (this.monitoring) {
            throw new Error('La surveillance est déjà en cours');
        }

        this.monitoring = true;
        const ips = this.parseIpRange(config.network.localNetwork.ipRange);

        // Initialisation des équipements
        for (const ip of ips) {
            this.devices.set(ip, {
                ip,
                hostname: null,
                status: 'unknown',
                lastSeen: null
            });
        }

        // Démarrage de la surveillance
        this.interval = setInterval(() => this.checkDevices(), this.pingInterval);
        console.log(`Surveillance démarrée pour ${ips.length} équipements`);
    }

    async stopMonitoring() {
        if (!this.monitoring) {
            throw new Error('La surveillance n\'est pas en cours');
        }

        clearInterval(this.interval);
        this.monitoring = false;
        this.devices.clear();
        console.log('Surveillance arrêtée');
    }

    parseIpRange(ipRange) {
        const ips = new Set();
        const ranges = ipRange.split(',').map(range => range.trim());

        for (const range of ranges) {
            if (range.includes('-')) {
                const [start, end] = range.split('-').map(ip => ip.trim());
                const startParts = start.split('.').map(Number);
                const endParts = end.split('.').map(Number);

                for (let i = startParts[3]; i <= endParts[3]; i++) {
                    ips.add(`${startParts[0]}.${startParts[1]}.${startParts[2]}.${i}`);
                }
            } else {
                ips.add(range);
            }
        }

        return Array.from(ips);
    }

    async checkDevices() {
        if (!this.monitoring) return;

        const checks = Array.from(this.devices.keys()).map(ip => this.checkDevice(ip));
        await Promise.all(checks);
        this.emit('devices-update', Array.from(this.devices.values()));
    }

    async checkDevice(ip) {
        try {
            // Ping de l'équipement
            const pingResult = await ping.promise.probe(ip, {
                timeout: this.timeout / 1000,
                extra: ['-c', '1']
            });

            const device = this.devices.get(ip);
            const oldStatus = device.status;
            const newStatus = pingResult.alive ? 'online' : 'offline';

            // Mise à jour du statut
            device.status = newStatus;
            device.lastSeen = new Date();
            device.latency = pingResult.time;

            // Résolution du nom d'hôte
            if (newStatus === 'online' && !device.hostname) {
                try {
                    const hostnames = await dns.reverse(ip);
                    device.hostname = hostnames[0];
                } catch (error) {
                    device.hostname = null;
                }
            }

            // Sauvegarde dans la base de données
            await db.updateDevice(ip, device.hostname, newStatus);
            if (pingResult.alive) {
                await db.addMetric(device.id, pingResult.time);
            }

            // Émission des métriques
            this.emit('metrics-update', {
                deviceId: device.id,
                timestamp: new Date(),
                latency: pingResult.time
            });

            // Gestion des alertes
            if (oldStatus === 'online' && newStatus === 'offline') {
                await this.handleDeviceDown(device);
            } else if (oldStatus === 'offline' && newStatus === 'online') {
                await this.handleDeviceUp(device);
            }

        } catch (error) {
            console.error(`Erreur lors de la vérification de ${ip}:`, error);
            const device = this.devices.get(ip);
            if (device) {
                device.status = 'error';
                device.lastSeen = new Date();
                await db.updateDevice(ip, device.hostname, 'error');
            }
        }
    }

    async handleDeviceDown(device) {
        const alert = {
            type: 'device_down',
            message: `L'équipement ${device.hostname || device.ip} n'est plus accessible`,
            deviceId: device.id
        };

        await db.addAlert(device.id, alert.type, alert.message);
        this.emit('alert', alert);
    }

    async handleDeviceUp(device) {
        const alert = {
            type: 'device_up',
            message: `L'équipement ${device.hostname || device.ip} est de nouveau accessible`,
            deviceId: device.id
        };

        await db.addAlert(device.id, alert.type, alert.message);
        this.emit('alert', alert);
    }

    getDevices() {
        return Array.from(this.devices.values());
    }

    isMonitoring() {
        return this.monitoring;
    }
}

module.exports = NetworkMonitor; 