// Mock de sqlite3 avant l'import de Database
jest.mock('sqlite3', () => {
    const mockDb = {
        run: jest.fn(),
        get: jest.fn(),
        all: jest.fn(),
        serialize: jest.fn((callback) => {
            callback();
            return mockDb;
        }),
        close: jest.fn()
    };

    const mockVerbose = jest.fn(() => ({
        Database: jest.fn(() => mockDb)
    }));

    return {
        verbose: mockVerbose
    };
});

// Mock de path avant l'import de Database
jest.mock('path', () => ({
    join: jest.fn(() => 'mock/path/database.sqlite')
}));

// Mock de bcrypt avant l'import de Database
jest.mock('bcrypt', () => ({
    hash: jest.fn(() => Promise.resolve('hashed_password'))
}));

// Import de Database après les mocks
const Database = require('../database');

describe('Database', () => {
    let db;
    let mockDb;

    beforeEach(() => {
        // Réinitialiser tous les mocks
        jest.clearAllMocks();

        // Créer une nouvelle instance de Database
        db = new Database();
        mockDb = db.db;
    });

    describe('updateDevice', () => {
        it('should update device information', async () => {
            const device = {
                ip: '192.168.1.1',
                hostname: 'test-device',
                status: 'online',
                openPorts: JSON.stringify([80, 443])
            };

            mockDb.run.mockImplementation((query, params, callback) => {
                callback(null, { lastID: 1 });
            });

            const result = await db.updateDevice(device);
            expect(result).toHaveProperty('id', 1);
            expect(result).toHaveProperty('ip', device.ip);
            expect(mockDb.run).toHaveBeenCalled();
        });

        it('should handle database errors', async () => {
            const device = {
                ip: '192.168.1.1',
                hostname: 'test-device',
                status: 'online'
            };

            mockDb.run.mockImplementation((query, params, callback) => {
                callback(new Error('Database error'));
            });

            await expect(db.updateDevice(device)).rejects.toThrow('Database error');
        });
    });

    describe('getDevices', () => {
        it('should return all devices', async () => {
            const mockDevices = [
                { id: 1, ip: '192.168.1.1', status: 'online' },
                { id: 2, ip: '192.168.1.2', status: 'offline' }
            ];

            mockDb.all.mockImplementation((query, callback) => {
                callback(null, mockDevices);
            });

            const devices = await db.getDevices();
            expect(devices).toEqual(mockDevices);
            expect(mockDb.all).toHaveBeenCalled();
        });

        it('should handle database errors', async () => {
            mockDb.all.mockImplementation((query, callback) => {
                callback(new Error('Database error'));
            });

            await expect(db.getDevices()).rejects.toThrow('Database error');
        });
    });

    describe('addMetric', () => {
        it('should add a new metric', async () => {
            const metric = {
                deviceId: 1,
                type: 'ping',
                value: 50
            };

            mockDb.run.mockImplementation((query, params, callback) => {
                callback(null, { lastID: 1 });
            });

            const result = await db.addMetric(metric);
            expect(result).toHaveProperty('id', 1);
            expect(result).toHaveProperty('type', metric.type);
            expect(mockDb.run).toHaveBeenCalled();
        });

        it('should handle database errors', async () => {
            const metric = {
                deviceId: 1,
                type: 'ping',
                value: 50
            };

            mockDb.run.mockImplementation((query, params, callback) => {
                callback(new Error('Database error'));
            });

            await expect(db.addMetric(metric)).rejects.toThrow('Database error');
        });
    });

    describe('getMetrics', () => {
        it('should return metrics for a device', async () => {
            const mockMetrics = [
                { id: 1, deviceId: 1, type: 'ping', value: 50 },
                { id: 2, deviceId: 1, type: 'ping', value: 45 }
            ];

            mockDb.all.mockImplementation((query, params, callback) => {
                callback(null, mockMetrics);
            });

            const metrics = await db.getMetrics(1, 'ping');
            expect(metrics).toEqual(mockMetrics);
            expect(mockDb.all).toHaveBeenCalledWith(
                expect.stringContaining('SELECT * FROM metrics'),
                [1, 'ping'],
                expect.any(Function)
            );
        });

        it('should handle database errors', async () => {
            mockDb.all.mockImplementation((query, params, callback) => {
                callback(new Error('Database error'));
            });

            await expect(db.getMetrics(1, 'ping')).rejects.toThrow('Database error');
            expect(mockDb.all).toHaveBeenCalledWith(
                expect.stringContaining('SELECT * FROM metrics'),
                [1, 'ping'],
                expect.any(Function)
            );
        });

        it('should return empty array when no metrics found', async () => {
            mockDb.all.mockImplementation((query, params, callback) => {
                callback(null, []);
            });

            const metrics = await db.getMetrics(1, 'ping');
            expect(metrics).toEqual([]);
            expect(mockDb.all).toHaveBeenCalledWith(
                expect.stringContaining('SELECT * FROM metrics'),
                [1, 'ping'],
                expect.any(Function)
            );
        });
    });
}); 