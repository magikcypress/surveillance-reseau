const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const db = require('./database');

class Auth {
    constructor() {
        this.jwtSecret = process.env.JWT_SECRET || 'your-secret-key';
        if (!this.jwtSecret) {
            console.warn('Warning: JWT_SECRET is not set. Using default secret key.');
        }
        // Lier les méthodes à l'instance
        this.authenticate = this.authenticate.bind(this);
        this.verifyToken = this.verifyToken.bind(this);
    }

    async register(userData) {
        try {
            // Vérifier si l'utilisateur existe déjà
            const existingUser = await db.getUserByUsername(userData.username);
            if (existingUser) {
                throw new Error('Username already exists');
            }

            // Hasher le mot de passe
            const hashedPassword = await bcrypt.hash(userData.password, 10);

            // Créer l'utilisateur
            const user = await db.createUser({
                username: userData.username,
                password: hashedPassword,
                role: userData.role || 'user'
            });

            // Générer le token
            const token = this.generateToken(user);

            return {
                user: {
                    id: user.id,
                    username: user.username,
                    role: user.role
                },
                token
            };
        } catch (error) {
            console.error('Registration error:', error);
            throw new Error('Registration failed: ' + error.message);
        }
    }

    async login(credentials) {
        try {
            // Vérifier les identifiants
            const user = await db.getUserByUsername(credentials.username);
            if (!user) {
                throw new Error('Invalid credentials');
            }

            // Vérifier le mot de passe
            const isValid = await bcrypt.compare(credentials.password, user.password);
            if (!isValid) {
                throw new Error('Invalid credentials');
            }

            // Générer le token
            const token = this.generateToken(user);

            return {
                user: {
                    id: user.id,
                    username: user.username,
                    role: user.role
                },
                token
            };
        } catch (error) {
            console.error('Login error:', error);
            throw new Error('Login failed: ' + error.message);
        }
    }

    generateToken(user) {
        return jwt.sign(
            {
                id: user.id,
                username: user.username,
                role: user.role
            },
            this.jwtSecret,
            { expiresIn: '24h' }
        );
    }

    async verifyToken(token) {
        try {
            const decoded = jwt.verify(token, this.jwtSecret);
            const user = await db.getUserById(decoded.id);

            if (!user) {
                throw new Error('User not found');
            }

            return {
                id: user.id,
                username: user.username,
                role: user.role
            };
        } catch (error) {
            if (error.name === 'TokenExpiredError') {
                throw new Error('Token expired');
            }
            throw new Error('Invalid token');
        }
    }

    async authenticate(req, res, next) {
        try {
            const authHeader = req.headers.authorization;
            if (!authHeader) {
                return res.status(401).json({
                    error: 'No token provided',
                    code: 'AUTH_NO_TOKEN'
                });
            }

            const token = authHeader.split(' ')[1];
            if (!token) {
                return res.status(401).json({
                    error: 'Invalid token format',
                    code: 'AUTH_INVALID_FORMAT'
                });
            }

            try {
                const user = await this.verifyToken(token);
                req.user = user;
                next();
            } catch (error) {
                if (error.message === 'Token expired') {
                    return res.status(401).json({
                        error: 'Token expired',
                        code: 'AUTH_TOKEN_EXPIRED'
                    });
                }
                return res.status(401).json({
                    error: 'Invalid token',
                    code: 'AUTH_INVALID_TOKEN'
                });
            }
        } catch (error) {
            console.error('Authentication error:', error);
            return res.status(500).json({
                error: 'Authentication failed',
                code: 'AUTH_SERVER_ERROR'
            });
        }
    }

    async logout(req, res) {
        try {
            // Dans une implémentation plus avancée, on pourrait invalider le token
            // Pour l'instant, on se contente de renvoyer une réponse de succès
            res.json({ message: 'Logged out successfully' });
        } catch (error) {
            console.error('Logout error:', error);
            res.status(500).json({
                error: 'Logout failed',
                code: 'AUTH_LOGOUT_ERROR'
            });
        }
    }

    requireRole(role) {
        return async (req, res, next) => {
            try {
                console.log('Vérification du rôle...');
                const user = await db.getUser(req.user.username);
                if (!user) {
                    console.log('Utilisateur non trouvé');
                    return res.status(401).json({ message: 'Utilisateur non trouvé' });
                }
                if (user.role !== role) {
                    console.log('Rôle insuffisant');
                    return res.status(403).json({ message: 'Accès refusé' });
                }
                console.log('Rôle vérifié avec succès');
                next();
            } catch (error) {
                console.error('Erreur de vérification du rôle:', error);
                res.status(500).json({ message: 'Erreur serveur' });
            }
        };
    }
}

// Exporter une instance de la classe Auth
const auth = new Auth();
module.exports = auth; 