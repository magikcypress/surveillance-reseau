// Configuration globale pour les tests
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-secret';
process.env.SESSION_SECRET = 'test-session-secret';

// Mock de la base de données
jest.mock('../database', () => {
    return {
        initializeDatabase: jest.fn(),
        updateDevice: jest.fn(),
        getDevices: jest.fn(),
        addMetric: jest.fn(),
        getMetrics: jest.fn(),
        saveSpeedTest: jest.fn(),
        getSpeedTestHistory: jest.fn(),
        saveLatencyMeasurement: jest.fn()
    };
});

// Mock de Socket.IO
jest.mock('socket.io', () => {
    return jest.fn().mockImplementation(() => ({
        on: jest.fn(),
        emit: jest.fn()
    }));
});

// Mock de express-session
jest.mock('express-session', () => {
    return jest.fn().mockImplementation(() => {
        return (req, res, next) => next();
    });
});

// Nettoyage après chaque test
afterEach(() => {
    jest.clearAllMocks();
}); 