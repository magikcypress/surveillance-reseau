const Auth = require('../auth');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

jest.mock('jsonwebtoken');
jest.mock('bcrypt');

describe('Auth', () => {
    let auth;
    const mockUser = {
        id: 1,
        username: 'testuser',
        password: 'hashedpassword',
        role: 'user'
    };

    beforeEach(() => {
        auth = new Auth();
        jest.clearAllMocks();
    });

    describe('register', () => {
        it('should register a new user successfully', async () => {
            bcrypt.hash.mockResolvedValue('hashedpassword');
            const result = await auth.register('testuser', 'password123', 'user');
            expect(result).toHaveProperty('id');
            expect(result).toHaveProperty('username', 'testuser');
            expect(result).toHaveProperty('role', 'user');
            expect(result).not.toHaveProperty('password');
        });

        it('should throw error if username already exists', async () => {
            await expect(auth.register('existinguser', 'password123', 'user'))
                .rejects
                .toThrow('Username already exists');
        });
    });

    describe('login', () => {
        it('should login successfully with correct credentials', async () => {
            bcrypt.compare.mockResolvedValue(true);
            jwt.sign.mockReturnValue('mocktoken');

            const result = await auth.login('testuser', 'password123');
            expect(result).toHaveProperty('token', 'mocktoken');
            expect(result).toHaveProperty('user');
            expect(result.user).not.toHaveProperty('password');
        });

        it('should throw error with incorrect password', async () => {
            bcrypt.compare.mockResolvedValue(false);
            await expect(auth.login('testuser', 'wrongpassword'))
                .rejects
                .toThrow('Invalid credentials');
        });
    });

    describe('verifyToken', () => {
        it('should verify valid token', () => {
            jwt.verify.mockReturnValue({ userId: 1 });
            const result = auth.verifyToken('validtoken');
            expect(result).toHaveProperty('userId', 1);
        });

        it('should throw error with invalid token', () => {
            jwt.verify.mockImplementation(() => {
                throw new Error('Invalid token');
            });
            expect(() => auth.verifyToken('invalidtoken')).toThrow('Invalid token');
        });
    });
}); 