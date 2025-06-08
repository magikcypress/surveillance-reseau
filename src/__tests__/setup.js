// Configuration globale pour les tests
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-secret';
process.env.SESSION_SECRET = 'test-session-secret';

// Configuration de Jest
jest.setTimeout(10000); // Augmenter le timeout pour les tests

// Mock de la base de données
jest.mock('../database', () => ({
    initializeDatabase: jest.fn(),
    updateDevice: jest.fn(),
    getDevices: jest.fn(),
    addMetric: jest.fn(),
    getMetrics: jest.fn(),
    saveSpeedTest: jest.fn(),
    getSpeedTestHistory: jest.fn(),
    saveLatencyMeasurement: jest.fn()
}));

// Mock de Socket.IO
jest.mock('socket.io', () => {
    return jest.fn().mockImplementation(() => ({
        on: jest.fn(),
        emit: jest.fn(),
        disconnect: jest.fn()
    }));
});

// Mock de express-session
jest.mock('express-session', () => {
    return jest.fn().mockImplementation(() => {
        return (req, res, next) => next();
    });
});

// Configuration globale pour tous les tests
global.beforeAll = beforeAll;
global.beforeEach = beforeEach;
global.afterEach = afterEach;
global.afterAll = afterAll;

// Configuration initiale avant tous les tests
beforeAll(() => {
    // Configuration initiale
});

// Réinitialisation avant chaque test
beforeEach(() => {
    jest.clearAllMocks();
});

// Nettoyage après chaque test
afterEach(() => {
    jest.clearAllMocks();
});

// Nettoyage final après tous les tests
afterAll(() => {
    // Nettoyage final
}); 