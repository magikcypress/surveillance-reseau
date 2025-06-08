const config = {
    // Configuration du serveur
    port: process.env.PORT || 3000,

    // Configuration de la base de données
    database: {
        path: process.env.DB_PATH || './src/data/database.json'
    },

    // Configuration des notifications
    notifications: {
        email: {
            enabled: process.env.EMAIL_ENABLED === 'true',
            smtp: {
                host: process.env.SMTP_HOST || 'localhost',
                port: parseInt(process.env.SMTP_PORT) || 587,
                secure: process.env.SMTP_SECURE === 'true',
                auth: {
                    user: process.env.SMTP_USER || 'user@example.com',
                    pass: process.env.SMTP_PASS || 'password'
                }
            },
            from: process.env.SMTP_FROM || 'user@example.com'
        }
    },

    // Configuration du réseau local
    network: {
        localNetwork: {
            subnet: '192.168.1.0/24',
            gateway: '192.168.1.254',
            devices: [
                {
                    ip: '192.168.1.58',
                    mac: 'b8:27:eb:e6:42:2d',
                    name: 'Device 1'
                },
                {
                    ip: '192.168.1.104',
                    mac: '96:e8:40:ee:aa:2e',
                    name: 'Device 2'
                },
                {
                    ip: '192.168.1.130',
                    mac: '1e:25:f4:4d:78:c',
                    name: 'Device 3'
                },
                {
                    ip: '192.168.1.150',
                    mac: 'bc:d0:74:51:d8:2f',
                    name: 'Device 4'
                }
            ],
            scanInterval: 60000, // Intervalle de scan en millisecondes (1 minute)
            pingTimeout: 1000,  // Timeout pour le ping en millisecondes
            retryCount: 3       // Nombre de tentatives de ping
        }
    }
};

module.exports = config; 