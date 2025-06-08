const EventEmitter = require('events');
const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);
const https = require('https');
const fs = require('fs');
const path = require('path');

class SpeedTest extends EventEmitter {
    constructor() {
        super();
        this.testing = false;
        this.testFileSize = 10 * 1024 * 1024; // 10MB
    }

    async runSpeedTest() {
        if (this.testing) {
            throw new Error('Un test est déjà en cours');
        }

        this.testing = true;
        try {
            // Test de téléchargement
            const downloadResult = await this.testDownload();

            // Test d'upload
            const uploadResult = await this.testUpload();

            this.testing = false;
            return {
                download: downloadResult,
                upload: uploadResult,
                timestamp: new Date()
            };
        } catch (error) {
            this.testing = false;
            throw error;
        }
    }

    async testDownload() {
        return new Promise((resolve, reject) => {
            const startTime = Date.now();
            let downloadedBytes = 0;

            const options = {
                hostname: 'speed.cloudflare.com',
                path: '/__down?bytes=' + this.testFileSize,
                method: 'GET'
            };

            const req = https.request(options, (res) => {
                res.on('data', (chunk) => {
                    downloadedBytes += chunk.length;
                });

                res.on('end', () => {
                    const endTime = Date.now();
                    const duration = (endTime - startTime) / 1000; // en secondes
                    const speed = (downloadedBytes * 8) / (1024 * 1024 * duration); // Mbps

                    resolve({
                        speed,
                        duration,
                        bytes: downloadedBytes
                    });
                });
            });

            req.on('error', (error) => {
                reject(new Error('Échec du test de téléchargement: ' + error.message));
            });

            req.end();
        });
    }

    async testUpload() {
        return new Promise((resolve, reject) => {
            const startTime = Date.now();
            const testData = Buffer.alloc(this.testFileSize);

            const options = {
                hostname: 'speed.cloudflare.com',
                path: '/__up',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/octet-stream',
                    'Content-Length': this.testFileSize
                }
            };

            const req = https.request(options, (res) => {
                let responseData = '';
                res.on('data', (chunk) => {
                    responseData += chunk;
                });

                res.on('end', () => {
                    const endTime = Date.now();
                    const duration = (endTime - startTime) / 1000; // en secondes
                    const speed = (this.testFileSize * 8) / (1024 * 1024 * duration); // Mbps

                    resolve({
                        speed,
                        duration,
                        bytes: this.testFileSize
                    });
                });
            });

            req.on('error', (error) => {
                reject(new Error('Échec du test d\'upload: ' + error.message));
            });

            req.write(testData);
            req.end();
        });
    }

    async scanNetwork() {
        try {
            // Utilisation de nmap pour scanner le réseau
            const { stdout } = await execPromise('nmap -sn 192.168.1.0/24');

            // Extraction des IPs actives
            const ipRegex = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g;
            const ips = stdout.match(ipRegex) || [];

            // Filtrage des doublons
            return [...new Set(ips)];
        } catch (error) {
            console.error('Erreur lors du scan réseau:', error);
            throw new Error('Échec du scan réseau');
        }
    }
}

module.exports = SpeedTest; 