const Auth = require('../auth');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const db = require('../database');

// Mock des dépendances
jest.mock('jsonwebtoken');
jest.mock('bcrypt');
jest.mock('../database');

describe('Auth', () => {
    let auth;
    const mockUser = {
        id: 1,
        username: 'testuser',
        password: 'hashedpassword',
        role: 'user'
    };

    beforeEach(() => {
        // Réinitialiser les mocks
        jest.clearAllMocks();

        // Configurer les mocks
        jwt.sign.mockReturnValue('mock-token');
        bcrypt.hash.mockResolvedValue('hashedpassword');
        bcrypt.compare.mockResolvedValue(true);

        // Mock de la base de données
        db.getUserByUsername = jest.fn();
        db.createUser = jest.fn();

        // Créer une nouvelle instance d'Auth pour chaque test
        auth = new Auth();
    });

    describe('register', () => {
        it('should register a new user successfully', async () => {
            const userData = {
                username: 'newuser',
                password: 'password123',
                role: 'user'
            };

            db.getUserByUsername.mockResolvedValue(null);
            db.createUser.mockResolvedValue({
                id: 1,
                username: userData.username,
                role: userData.role
            });

            const result = await auth.register(userData);

            expect(result).toHaveProperty('id');
            expect(result).toHaveProperty('username', userData.username);
            expect(result).toHaveProperty('role', userData.role);
            expect(result).not.toHaveProperty('password');
            expect(bcrypt.hash).toHaveBeenCalledWith(userData.password, 10);
        });

        it('should throw error if username already exists', async () => {
            const userData = {
                username: 'testuser',
                password: 'password123',
                role: 'user'
            };

            db.getUserByUsername.mockResolvedValue(mockUser);

            await expect(auth.register(userData)).rejects.toThrow('Username already exists');
        });
    });

    describe('login', () => {
        it('should login successfully with correct credentials', async () => {
            const credentials = {
                username: 'testuser',
                password: 'password123'
            };

            db.getUserByUsername.mockResolvedValue(mockUser);

            const result = await auth.login(credentials);

            expect(result).toHaveProperty('token', 'mock-token');
            expect(result).toHaveProperty('user');
            expect(result.user).toHaveProperty('username', credentials.username);
            expect(result.user).not.toHaveProperty('password');
            expect(bcrypt.compare).toHaveBeenCalledWith(credentials.password, mockUser.password);
        });

        it('should throw error with incorrect password', async () => {
            const credentials = {
                username: 'testuser',
                password: 'wrongpassword'
            };

            db.getUserByUsername.mockResolvedValue(mockUser);
            bcrypt.compare.mockResolvedValueOnce(false);

            await expect(auth.login(credentials)).rejects.toThrow('Invalid credentials');
        });
    });

    describe('verifyToken', () => {
        it('should verify a valid token', async () => {
            const token = 'valid-token';
            jwt.verify.mockReturnValueOnce({ id: 1 });
            db.getUserById = jest.fn().mockResolvedValueOnce(mockUser);

            const result = await auth.verifyToken(token);

            expect(result).toBe(true);
            expect(jwt.verify).toHaveBeenCalledWith(token, process.env.JWT_SECRET);
        });

        it('should throw error for invalid token', async () => {
            const token = 'invalid-token';
            jwt.verify.mockImplementationOnce(() => {
                throw new Error('Invalid token');
            });

            await expect(auth.verifyToken(token)).rejects.toThrow('Invalid token');
        });
    });
}); 