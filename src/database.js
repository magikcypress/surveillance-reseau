const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');

class Database {
    constructor() {
        this.dbPath = path.join(__dirname, 'data', 'network-monitor.db');
        this.ensureDataDirectory();
        this.db = new sqlite3.Database(this.dbPath);
        this.initializeDatabase();
    }

    ensureDataDirectory() {
        const dataDir = path.join(__dirname, 'data');
        if (!fs.existsSync(dataDir)) {
            fs.mkdirSync(dataDir, { recursive: true });
        }
    }

    async initializeDatabase() {
        return new Promise((resolve, reject) => {
            this.db.serialize(() => {
                // Table des utilisateurs
                this.db.run(`
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        role TEXT DEFAULT 'user',
                        last_login DATETIME,
                        last_logout DATETIME,
                        is_active BOOLEAN DEFAULT TRUE,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                `);

                // Table des appareils
                this.db.run(`
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

                // Table des métriques
                this.db.run(`
                    CREATE TABLE IF NOT EXISTS metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        device_id INTEGER NOT NULL,
                        type TEXT NOT NULL,
                        value REAL NOT NULL,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (device_id) REFERENCES devices (id)
                    )
                `);

                // Table des tests de vitesse
                this.db.run(`
                    CREATE TABLE IF NOT EXISTS speed_tests (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        download REAL NOT NULL,
                        upload REAL NOT NULL,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                `);

                // Table des alertes
                this.db.run(`
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        device_id INTEGER,
                        type TEXT NOT NULL,
                        message TEXT NOT NULL,
                        resolved BOOLEAN DEFAULT FALSE,
                        resolved_at DATETIME,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (device_id) REFERENCES devices (id)
                    )
                `);

                // Table de l'historique de latence
                this.db.run(`
                    CREATE TABLE IF NOT EXISTS latency_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        latency REAL NOT NULL
                    )
                `, async (err) => {
                    if (err) {
                        reject(err);
                        return;
                    }

                    try {
                        // Vérifier si un utilisateur admin existe déjà
                        const adminExists = await this.getUserByUsername('admin');
                        if (!adminExists) {
                            // Créer un utilisateur admin par défaut
                            const hashedPassword = await bcrypt.hash('admin', 10);
                            await this.createUser('admin', hashedPassword, 'admin@example.com');
                        }
                        resolve();
                    } catch (error) {
                        console.error('Erreur lors de l\'initialisation de la base de données:', error);
                        reject(error);
                    }
                });
            });
        });
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

    async getUserByEmail(email) {
        return new Promise((resolve, reject) => {
            this.db.get(
                'SELECT * FROM users WHERE email = ?',
                [email],
                (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                }
            );
        });
    }

    async updateLastLogin(userId) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
                [userId],
                function (err) {
                    if (err) reject(err);
                    else resolve(this.changes);
                }
            );
        });
    }

    async updateLastLogout(userId) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'UPDATE users SET last_logout = CURRENT_TIMESTAMP WHERE id = ?',
                [userId],
                function (err) {
                    if (err) reject(err);
                    else resolve(this.changes);
                }
            );
        });
    }

    async updatePassword(userId, hashedPassword) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'UPDATE users SET password = ? WHERE id = ?',
                [hashedPassword, userId],
                function (err) {
                    if (err) reject(err);
                    else resolve(this.changes);
                }
            );
        });
    }

    async deleteUser(userId) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'DELETE FROM users WHERE id = ?',
                [userId],
                function (err) {
                    if (err) reject(err);
                    else resolve(this.changes > 0);
                }
            );
        });
    }

    async getAllUsers() {
        return new Promise((resolve, reject) => {
            this.db.all(
                'SELECT id, username, email, role, last_login, last_logout, is_active, created_at FROM users ORDER BY created_at DESC',
                (err, rows) => {
                    if (err) reject(err);
                    else resolve(rows);
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

    async getDeviceById(id) {
        return new Promise((resolve, reject) => {
            this.db.get('SELECT * FROM devices WHERE id = ?', [id], (err, row) => {
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

    // Opérations sur les tests de vitesse
    async saveSpeedTest(speedTest) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'INSERT INTO speed_tests (download, upload) VALUES (?, ?)',
                [speedTest.download, speedTest.upload],
                function (err) {
                    if (err) reject(err);
                    else resolve({ id: this.lastID, ...speedTest });
                }
            );
        });
    }

    async getSpeedTestHistory() {
        return new Promise((resolve, reject) => {
            this.db.all(
                'SELECT * FROM speed_tests ORDER BY timestamp DESC LIMIT 100',
                (err, rows) => {
                    if (err) reject(err);
                    else resolve(rows);
                }
            );
        });
    }

    // Fermeture de la connexion
    close() {
        return new Promise((resolve, reject) => {
            this.db.close((err) => {
                if (err) reject(err);
                else resolve();
            });
        });
    }
}

// Exporter la classe Database
module.exports = Database; 