const Database = require('../database');
const sqlite3 = require('sqlite3');

jest.mock('sqlite3');

describe('Database', () => {
    let db;
    const mockRun = jest.fn();
    const mockAll = jest.fn();
    const mockGet = jest.fn();

    beforeEach(() => {
        mockRun.mockClear();
        mockAll.mockClear();
        mockGet.mockClear();

        const mockDb = {
            run: mockRun,
            all: mockAll,
            get: mockGet
        };

        sqlite3.Database.mockImplementation(() => mockDb);
        db = new Database();
    });

    describe('updateDevice', () => {
        it('should update device information', async () => {
            mockRun.mockImplementation((query, params, callback) => {
                callback(null);
            });

            await db.updateDevice('192.168.1.1', 'test-host', 'online', []);
            expect(mockRun).toHaveBeenCalled();
        });

        it('should handle database errors', async () => {
            mockRun.mockImplementation((query, params, callback) => {
                callback(new Error('Database error'));
            });

            await expect(db.updateDevice('192.168.1.1', 'test-host', 'online', []))
                .rejects
                .toThrow('Database error');
        });
    });

    describe('getDevices', () => {
        it('should return all devices', async () => {
            const mockDevices = [
                { ip: '192.168.1.1', status: 'online' },
                { ip: '192.168.1.2', status: 'offline' }
            ];

            mockAll.mockImplementation((query, callback) => {
                callback(null, mockDevices);
            });

            const devices = await db.getDevices();
            expect(devices).toEqual(mockDevices);
        });

        it('should handle database errors', async () => {
            mockAll.mockImplementation((query, callback) => {
                callback(new Error('Database error'));
            });

            await expect(db.getDevices()).rejects.toThrow('Database error');
        });
    });

    describe('addMetric', () => {
        it('should add a new metric', async () => {
            mockRun.mockImplementation((query, params, callback) => {
                callback(null);
            });

            await db.addMetric(1, 10.5);
            expect(mockRun).toHaveBeenCalled();
        });

        it('should handle database errors', async () => {
            mockRun.mockImplementation((query, params, callback) => {
                callback(new Error('Database error'));
            });

            await expect(db.addMetric(1, 10.5)).rejects.toThrow('Database error');
        });
    });

    describe('getMetrics', () => {
        it('should return metrics for a device', async () => {
            const mockMetrics = [
                { timestamp: '2024-01-01', value: 10.5 },
                { timestamp: '2024-01-02', value: 11.2 }
            ];

            mockAll.mockImplementation((query, params, callback) => {
                callback(null, mockMetrics);
            });

            const metrics = await db.getMetrics(1);
            expect(metrics).toEqual(mockMetrics);
        });

        it('should handle database errors', async () => {
            mockAll.mockImplementation((query, params, callback) => {
                callback(new Error('Database error'));
            });

            await expect(db.getMetrics(1)).rejects.toThrow('Database error');
        });
    });
}); 