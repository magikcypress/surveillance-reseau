const NetworkMonitor = require('../network-monitor');
const ping = require('ping');
const dns = require('dns').promises;
const db = require('../database');

// Mock des dépendances
jest.mock('ping');
jest.mock('dns');
jest.mock('../database');
jest.mock('../notifier');

describe('NetworkMonitor', () => {
    let networkMonitor;
    const mockIo = {
        emit: jest.fn()
    };

    beforeEach(() => {
        networkMonitor = new NetworkMonitor(mockIo);
        jest.clearAllMocks();
    });

    describe('scanPort', () => {
        it('should detect an open port', async () => {
            const result = await networkMonitor.scanPort('127.0.0.1', 80);
            expect(result).toHaveProperty('port', 80);
            expect(result).toHaveProperty('status');
            expect(result).toHaveProperty('service');
        });
    });

    describe('getServiceName', () => {
        it('should return correct service name for known port', () => {
            expect(networkMonitor.getServiceName(80)).toBe('HTTP');
            expect(networkMonitor.getServiceName(443)).toBe('HTTPS');
        });

        it('should return Unknown for unknown port', () => {
            expect(networkMonitor.getServiceName(9999)).toBe('Unknown');
        });
    });

    describe('scanDevice', () => {
        it('should scan all common ports', async () => {
            const result = await networkMonitor.scanDevice('127.0.0.1');
            expect(result).toHaveProperty('ip', '127.0.0.1');
            expect(result).toHaveProperty('openPorts');
            expect(result).toHaveProperty('timestamp');
        });
    });

    describe('checkDevice', () => {
        beforeEach(() => {
            ping.promise.probe.mockResolvedValue({
                alive: true,
                time: 10
            });
            dns.reverse.mockResolvedValue(['localhost']);
        });

        it('should update device status when online', async () => {
            await networkMonitor.checkDevice('127.0.0.1');
            expect(db.updateDevice).toHaveBeenCalled();
        });

        it('should handle DNS resolution errors', async () => {
            dns.reverse.mockRejectedValue(new Error('DNS error'));
            await networkMonitor.checkDevice('127.0.0.1');
            expect(db.updateDevice).toHaveBeenCalled();
        });
    });
}); 