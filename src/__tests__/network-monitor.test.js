const NetworkMonitor = require('../network-monitor');
const net = require('net');
const dns = require('dns');
const db = require('../database');
const ping = require('ping');

// Mock des dépendances
jest.mock('net');
jest.mock('dns');
jest.mock('../database');
jest.mock('../notifier');
jest.mock('ping');

describe('NetworkMonitor', () => {
    let networkMonitor;
    let mockDb;

    beforeEach(() => {
        // Réinitialiser les mocks
        jest.clearAllMocks();

        // Configurer les mocks
        net.Socket.mockImplementation(() => ({
            setTimeout: jest.fn(),
            on: jest.fn(),
            connect: jest.fn(),
            destroy: jest.fn()
        }));

        dns.reverse = jest.fn();
        dns.lookup = jest.fn();

        // Créer une nouvelle instance pour chaque test
        networkMonitor = new NetworkMonitor();
        mockDb = {
            updateDevice: jest.fn(),
            addMetric: jest.fn()
        };
        db.mockImplementation(() => mockDb);
    });

    describe('scanPort', () => {
        it('should detect open port', async () => {
            // Mock net.Socket pour simuler un port ouvert
            const mockSocket = {
                connect: jest.fn((port, host, callback) => {
                    callback();
                    return mockSocket;
                }),
                on: jest.fn(),
                destroy: jest.fn()
            };
            net.Socket.mockImplementation(() => mockSocket);

            const result = await networkMonitor.scanPort('192.168.1.1', 80);
            expect(result).toBe(true);
            expect(mockSocket.connect).toHaveBeenCalledWith(80, '192.168.1.1', expect.any(Function));
        });

        it('should detect closed port', async () => {
            // Mock net.Socket pour simuler un port fermé
            const mockSocket = {
                connect: jest.fn((port, host, callback) => {
                    const error = new Error('ECONNREFUSED');
                    error.code = 'ECONNREFUSED';
                    callback(error);
                    return mockSocket;
                }),
                on: jest.fn(),
                destroy: jest.fn()
            };
            net.Socket.mockImplementation(() => mockSocket);

            const result = await networkMonitor.scanPort('192.168.1.1', 9999);
            expect(result).toBe(false);
            expect(mockSocket.connect).toHaveBeenCalledWith(9999, '192.168.1.1', expect.any(Function));
        });

        it('should handle connection timeout', async () => {
            // Mock net.Socket pour simuler un timeout
            const mockSocket = {
                connect: jest.fn((port, host, callback) => {
                    const error = new Error('ETIMEDOUT');
                    error.code = 'ETIMEDOUT';
                    callback(error);
                    return mockSocket;
                }),
                on: jest.fn(),
                destroy: jest.fn()
            };
            net.Socket.mockImplementation(() => mockSocket);

            const result = await networkMonitor.scanPort('192.168.1.1', 80);
            expect(result).toBe(false);
            expect(mockSocket.connect).toHaveBeenCalledWith(80, '192.168.1.1', expect.any(Function));
        });
    });

    describe('getServiceName', () => {
        it('should return service name for known port', () => {
            const service = networkMonitor.getServiceName(80);
            expect(service).toBe('http');
        });

        it('should return unknown for unknown port', () => {
            const service = networkMonitor.getServiceName(9999);
            expect(service).toBe('unknown');
        });
    });

    describe('scanDevice', () => {
        it('should scan device ports', async () => {
            const device = {
                ip: '192.168.1.1',
                hostname: 'test-device'
            };

            // Mock net.Socket pour simuler des ports ouverts
            const mockSocket = {
                connect: jest.fn((port, host, callback) => {
                    if (port === 80 || port === 443) {
                        callback();
                    } else {
                        const error = new Error('ECONNREFUSED');
                        error.code = 'ECONNREFUSED';
                        callback(error);
                    }
                    return mockSocket;
                }),
                on: jest.fn(),
                destroy: jest.fn()
            };
            net.Socket.mockImplementation(() => mockSocket);

            const result = await networkMonitor.scanDevice(device);
            expect(result).toHaveProperty('ip', device.ip);
            expect(result).toHaveProperty('openPorts');
            expect(Array.isArray(result.openPorts)).toBe(true);
            expect(result.openPorts).toContainEqual(expect.objectContaining({ port: 80 }));
            expect(result.openPorts).toContainEqual(expect.objectContaining({ port: 443 }));
        });
    });

    describe('checkDevice', () => {
        it('should update device status when online', async () => {
            const device = {
                ip: '192.168.1.1',
                hostname: 'test-device'
            };

            // Mock ping successful
            ping.promise.probe.mockResolvedValue({ alive: true });

            // Mock DNS resolution
            dns.promises.reverse.mockResolvedValue(['test-device.local']);

            await networkMonitor.checkDevice(device);

            expect(mockDb.updateDevice).toHaveBeenCalledWith(expect.objectContaining({
                ip: device.ip,
                status: 'online'
            }));
        });

        it('should update device status when offline', async () => {
            const device = {
                ip: '192.168.1.1',
                hostname: 'test-device'
            };

            // Mock ping failed
            ping.promise.probe.mockResolvedValue({ alive: false });

            await networkMonitor.checkDevice(device);

            expect(mockDb.updateDevice).toHaveBeenCalledWith(expect.objectContaining({
                ip: device.ip,
                status: 'offline'
            }));
        });

        it('should handle DNS resolution errors', async () => {
            const device = {
                ip: '192.168.1.1',
                hostname: 'test-device'
            };

            // Mock ping successful
            ping.promise.probe.mockResolvedValue({ alive: true });

            // Mock DNS resolution error
            dns.promises.reverse.mockRejectedValue(new Error('DNS resolution failed'));

            await networkMonitor.checkDevice(device);

            // Should still update device status as online
            expect(mockDb.updateDevice).toHaveBeenCalledWith(expect.objectContaining({
                ip: device.ip,
                status: 'online'
            }));
        });
    });
}); 