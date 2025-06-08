const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');

class Database {
    constructor() {
        this.dbPath = path.join(__dirname, 'data', 'network-monitor.db');
        this.ensureDataDirectory();
        this.db = new sqlite3.Database(this.dbPath);
        this.init();
    }

    ensureDataDirectory() {
        const dataDir = path.join(__dirname, 'data');
        if (!fs.existsSync(dataDir)) {
            fs.mkdirSync(dataDir, { recursive: true });
        }
    }

    async init() {
        await this.initDatabase();
    }

    async initDatabase() {
        // Créer la table des utilisateurs
        await this.db.run(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                role TEXT DEFAULT 'user',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Créer la table des appareils
        await this.db.run(`
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE,
                mac TEXT,
                hostname TEXT,
                status TEXT,
                last_seen DATETIME,
                open_ports TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Créer la table d'historique de latence
        await this.db.run(`
            CREATE TABLE IF NOT EXISTS latency_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                latency REAL NOT NULL
            )
        `);

        // Créer un utilisateur admin par défaut si aucun utilisateur n'existe
        try {
            const adminExists = await this.getUserByUsername('admin');
            if (!adminExists) {
                const hashedPassword = await bcrypt.hash('admin', 10);
                await this.createUser('admin', hashedPassword, 'admin');
                console.log('Utilisateur admin créé avec succès');
            }
        } catch (error) {
            console.error('Erreur lors de la création de l\'utilisateur admin:', error);
        }
    }

    // Méthodes pour les utilisateurs
    async createUser(username, password, email) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
                [username, password, email],
                function (err) {
                    if (err) reject(err);
                    else resolve(this.lastID);
                }
            );
        });
    }

    async getUser(username) {
        return new Promise((resolve, reject) => {
            this.db.get(
                'SELECT id, username, password, email, role FROM users WHERE username = ?',
                [username],
                (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                }
            );
        });
    }

    async getUserByUsername(username) {
        return new Promise((resolve, reject) => {
            this.db.get(
                'SELECT * FROM users WHERE username = ?',
                [username],
                (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                }
            );
        });
    }

    // Méthodes pour les équipements
    async updateDevice(ip, hostname, status, openPorts = []) {
        return new Promise((resolve, reject) => {
            const openPortsJson = JSON.stringify(openPorts);
            this.db.run(
                `INSERT OR REPLACE INTO devices (ip, hostname, status, last_seen, open_ports)
                 VALUES (?, ?, ?, CURRENT_TIMESTAMP, ?)`,
                [ip, hostname, status, openPortsJson],
                (err) => {
                    if (err) reject(err);
                    else resolve();
                }
            );
        });
    }

    async getAllDevices() {
        return new Promise((resolve, reject) => {
            this.db.all('SELECT * FROM devices ORDER BY last_seen DESC', (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
    }

    // Méthodes pour les métriques
    async addMetric(deviceId, latency) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'INSERT INTO metrics (device_id, latency) VALUES (?, ?)',
                [deviceId, latency],
                function (err) {
                    if (err) reject(err);
                    else resolve(this.lastID);
                }
            );
        });
    }

    async getMetrics(deviceId, startDate, endDate) {
        return new Promise((resolve, reject) => {
            const query = `
                SELECT * FROM metrics 
                WHERE device_id = ? 
                AND timestamp BETWEEN ? AND ?
                ORDER BY timestamp ASC
            `;
            this.db.all(query, [deviceId, startDate, endDate], (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
    }

    // Méthodes pour les alertes
    async addAlert(deviceId, type, message) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'INSERT INTO alerts (device_id, type, message) VALUES (?, ?, ?)',
                [deviceId, type, message],
                function (err) {
                    if (err) reject(err);
                    else resolve(this.lastID);
                }
            );
        });
    }

    async getAlerts() {
        return new Promise((resolve, reject) => {
            this.db.all(
                `SELECT a.*, d.ip, d.hostname 
                 FROM alerts a 
                 LEFT JOIN devices d ON a.device_id = d.id 
                 ORDER BY a.timestamp DESC`,
                (err, rows) => {
                    if (err) reject(err);
                    else resolve(rows);
                }
            );
        });
    }

    async resolveAlert(alertId) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'UPDATE alerts SET resolved = TRUE, resolved_at = CURRENT_TIMESTAMP WHERE id = ?',
                [alertId],
                function (err) {
                    if (err) reject(err);
                    else resolve(this.changes > 0);
                }
            );
        });
    }

    // Méthodes pour les rapports
    async generateReport(startDate, endDate) {
        return new Promise((resolve, reject) => {
            const report = {
                startDate,
                endDate,
                totalDevices: 0,
                uptime: 0,
                averageLatency: 0,
                alerts: []
            };

            this.db.serialize(() => {
                // Nombre total d'équipements
                this.db.get(
                    'SELECT COUNT(DISTINCT device_id) as count FROM metrics WHERE timestamp BETWEEN ? AND ?',
                    [startDate, endDate],
                    (err, row) => {
                        if (err) reject(err);
                        else report.totalDevices = row.count;
                    }
                );

                // Disponibilité moyenne
                this.db.get(
                    `SELECT AVG(CASE WHEN status = 'online' THEN 1 ELSE 0 END) as uptime 
                     FROM devices 
                     WHERE last_seen BETWEEN ? AND ?`,
                    [startDate, endDate],
                    (err, row) => {
                        if (err) reject(err);
                        else report.uptime = row.uptime || 0;
                    }
                );

                // Latence moyenne
                this.db.get(
                    'SELECT AVG(latency) as avgLatency FROM metrics WHERE timestamp BETWEEN ? AND ?',
                    [startDate, endDate],
                    (err, row) => {
                        if (err) reject(err);
                        else report.averageLatency = row.avgLatency || 0;
                    }
                );

                // Alertes
                this.db.all(
                    `SELECT a.*, d.ip, d.hostname 
                     FROM alerts a 
                     LEFT JOIN devices d ON a.device_id = d.id 
                     WHERE a.timestamp BETWEEN ? AND ?
                     ORDER BY a.timestamp DESC`,
                    [startDate, endDate],
                    (err, rows) => {
                        if (err) reject(err);
                        else {
                            report.alerts = rows;
                            resolve(report);
                        }
                    }
                );
            });
        });
    }

    // Nettoyage des anciennes données
    async cleanupOldData(daysToKeep) {
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - daysToKeep);

        return new Promise((resolve, reject) => {
            this.db.serialize(() => {
                this.db.run('DELETE FROM metrics WHERE timestamp < ?', [cutoffDate.toISOString()]);
                this.db.run('DELETE FROM alerts WHERE timestamp < ?', [cutoffDate.toISOString()]);
                this.db.run('VACUUM', (err) => {
                    if (err) reject(err);
                    else resolve();
                });
            });
        });
    }

    // Gestion des appareils
    async saveDevices(devices) {
        return new Promise((resolve, reject) => {
            this.db.run('BEGIN TRANSACTION', (err) => {
                if (err) {
                    reject(err);
                    return;
                }

                const stmt = this.db.prepare('INSERT OR REPLACE INTO devices (ip, hostname, status, latency, last_seen) VALUES (?, ?, ?, ?, ?)');

                devices.forEach(device => {
                    stmt.run(
                        device.ip,
                        device.hostname || null,
                        device.status || 'unknown',
                        device.latency || 0,
                        device.lastSeen || new Date().toISOString()
                    );
                });

                stmt.finalize();

                this.db.run('COMMIT', (err) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve();
                    }
                });
            });
        });
    }

    async getDevices() {
        return new Promise((resolve, reject) => {
            this.db.all('SELECT * FROM devices ORDER BY last_seen DESC', (err, rows) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(rows.map(row => ({
                        ip: row.ip,
                        hostname: row.hostname,
                        status: row.status,
                        latency: row.latency,
                        lastSeen: row.last_seen
                    })));
                }
            });
        });
    }

    async getDeviceByIP(ip) {
        return new Promise((resolve, reject) => {
            this.db.get('SELECT * FROM devices WHERE ip = ?', [ip], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });
    }

    async updateDeviceStatus(ip, status) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'UPDATE devices SET status = ?, last_seen = datetime("now") WHERE ip = ?',
                [status, ip],
                function (err) {
                    if (err) reject(err);
                    else resolve(this.changes);
                }
            );
        });
    }

    // Fonction pour sauvegarder une mesure de latence
    async saveLatencyMeasurement(latency) {
        return new Promise((resolve, reject) => {
            const timestamp = new Date().toISOString();
            this.db.run(
                'INSERT INTO latency_history (timestamp, latency) VALUES (?, ?)',
                [timestamp, latency],
                (err) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve();
                    }
                }
            );
        });
    }

    // Fonction pour récupérer l'historique des latences
    async getLatencyHistory(limit = 60) {
        return new Promise((resolve, reject) => {
            this.db.all(
                'SELECT timestamp, latency FROM latency_history ORDER BY timestamp DESC LIMIT ?',
                [limit],
                (err, rows) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(rows.map(row => ({
                            timestamp: row.timestamp,
                            latency: row.latency
                        })));
                    }
                }
            );
        });
    }

    // Méthode pour nettoyer l'historique de latence
    async cleanLatencyHistory(daysToKeep = 7) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'DELETE FROM latency_history WHERE timestamp < datetime("now", ?)',
                [`-${daysToKeep} days`],
                function (err) {
                    if (err) reject(err);
                    else resolve(this.changes);
                }
            );
        });
    }

    // Fonction pour supprimer tous les appareils
    async clearDevices() {
        return new Promise((resolve, reject) => {
            this.db.run('DELETE FROM devices', (err) => {
                if (err) {
                    console.error('Erreur lors de la suppression des appareils:', err);
                    reject(err);
                } else {
                    console.log('Tous les appareils ont été supprimés');
                    resolve();
                }
            });
        });
    }
}

module.exports = new Database(); 