const nodemailer = require('nodemailer');
const Database = require('./database');

class Notifier {
    constructor() {
        this.transporter = null;
        this.db = new Database();
        this.initializeTransporter();
    }

    initializeTransporter() {
        try {
            this.transporter = nodemailer.createTransport({
                host: process.env.SMTP_HOST,
                port: parseInt(process.env.SMTP_PORT) || 587,
                secure: process.env.SMTP_SECURE === 'true',
                auth: {
                    user: process.env.SMTP_USER,
                    pass: process.env.SMTP_PASS
                }
            });

            // Vérification de la configuration
            this.transporter.verify((error, success) => {
                if (error) {
                    console.error('Erreur de configuration SMTP:', error);
                } else {
                    console.log('Serveur SMTP prêt à envoyer des emails');
                }
            });
        } catch (error) {
            console.error('Erreur lors de l\'initialisation du transporteur SMTP:', error);
        }
    }

    async sendAlert(alert) {
        if (!this.transporter) {
            console.error('Transporteur SMTP non initialisé');
            return;
        }

        try {
            const device = await this.db.getDeviceById(alert.deviceId);
            if (!device) {
                throw new Error('Équipement non trouvé');
            }

            const mailOptions = {
                from: process.env.SMTP_FROM,
                to: process.env.SMTP_FROM, // Envoi à l'administrateur
                subject: `[Alerte] ${alert.type} - ${device.hostname || device.ip}`,
                html: `
                    <h2>Alerte de surveillance réseau</h2>
                    <p><strong>Type:</strong> ${alert.type}</p>
                    <p><strong>Message:</strong> ${alert.message}</p>
                    <p><strong>Équipement:</strong> ${device.hostname || device.ip}</p>
                    <p><strong>Date:</strong> ${new Date(alert.timestamp).toLocaleString()}</p>
                `
            };

            await this.transporter.sendMail(mailOptions);
            console.log(`Alerte envoyée pour ${device.hostname || device.ip}`);
        } catch (error) {
            console.error('Erreur lors de l\'envoi de l\'alerte:', error);
            throw error;
        }
    }

    async sendDailyReport() {
        if (!this.transporter) {
            console.error('Transporteur SMTP non initialisé');
            return;
        }

        try {
            const yesterday = new Date();
            yesterday.setDate(yesterday.getDate() - 1);
            yesterday.setHours(0, 0, 0, 0);

            const today = new Date();
            today.setHours(0, 0, 0, 0);

            const report = await this.db.generateReport(yesterday.toISOString(), today.toISOString());

            const mailOptions = {
                from: process.env.SMTP_FROM,
                to: process.env.SMTP_FROM,
                subject: 'Rapport quotidien de surveillance réseau',
                html: `
                    <h2>Rapport quotidien de surveillance réseau</h2>
                    <p><strong>Période:</strong> ${yesterday.toLocaleDateString()} - ${today.toLocaleDateString()}</p>
                    
                    <h3>Résumé</h3>
                    <ul>
                        <li>Nombre d'équipements: ${report.totalDevices}</li>
                        <li>Disponibilité moyenne: ${(report.uptime * 100).toFixed(2)}%</li>
                        <li>Latence moyenne: ${report.averageLatency.toFixed(2)} ms</li>
                    </ul>

                    <h3>Alertes</h3>
                    <table border="1" cellpadding="5" style="border-collapse: collapse;">
                        <tr>
                            <th>Date</th>
                            <th>Type</th>
                            <th>Message</th>
                            <th>Statut</th>
                        </tr>
                        ${report.alerts.map(alert => `
                            <tr>
                                <td>${new Date(alert.timestamp).toLocaleString()}</td>
                                <td>${alert.type}</td>
                                <td>${alert.message}</td>
                                <td>${alert.resolved ? 'Résolue' : 'Active'}</td>
                            </tr>
                        `).join('')}
                    </table>
                `
            };

            await this.transporter.sendMail(mailOptions);
            console.log('Rapport quotidien envoyé');
        } catch (error) {
            console.error('Erreur lors de l\'envoi du rapport quotidien:', error);
            throw error;
        }
    }

    async sendCustomReport(startDate, endDate, recipients) {
        if (!this.transporter) {
            console.error('Transporteur SMTP non initialisé');
            return;
        }

        try {
            const report = await this.db.generateReport(startDate, endDate);

            const mailOptions = {
                from: process.env.SMTP_FROM,
                to: recipients.join(', '),
                subject: `Rapport de surveillance réseau - ${new Date(startDate).toLocaleDateString()} à ${new Date(endDate).toLocaleDateString()}`,
                html: `
                    <h2>Rapport de surveillance réseau</h2>
                    <p><strong>Période:</strong> ${new Date(startDate).toLocaleDateString()} - ${new Date(endDate).toLocaleDateString()}</p>
                    
                    <h3>Résumé</h3>
                    <ul>
                        <li>Nombre d'équipements: ${report.totalDevices}</li>
                        <li>Disponibilité moyenne: ${(report.uptime * 100).toFixed(2)}%</li>
                        <li>Latence moyenne: ${report.averageLatency.toFixed(2)} ms</li>
                    </ul>

                    <h3>Alertes</h3>
                    <table border="1" cellpadding="5" style="border-collapse: collapse;">
                        <tr>
                            <th>Date</th>
                            <th>Type</th>
                            <th>Message</th>
                            <th>Statut</th>
                        </tr>
                        ${report.alerts.map(alert => `
                            <tr>
                                <td>${new Date(alert.timestamp).toLocaleString()}</td>
                                <td>${alert.type}</td>
                                <td>${alert.message}</td>
                                <td>${alert.resolved ? 'Résolue' : 'Active'}</td>
                            </tr>
                        `).join('')}
                    </table>
                `
            };

            await this.transporter.sendMail(mailOptions);
            console.log('Rapport personnalisé envoyé');
        } catch (error) {
            console.error('Erreur lors de l\'envoi du rapport personnalisé:', error);
            throw error;
        }
    }
}

module.exports = Notifier; 