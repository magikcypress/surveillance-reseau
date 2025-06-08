const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('./database');

class Auth {
    constructor() {
        this.secret = process.env.JWT_SECRET || 'your-secret-key';
        if (!this.secret || this.secret === 'your-secret-key') {
            console.warn('Attention: JWT_SECRET n\'est pas défini dans les variables d\'environnement');
        }
        // Lier les méthodes à l'instance
        this.authenticate = this.authenticate.bind(this);
        this.verifyToken = this.verifyToken.bind(this);
    }

    async register(username, password, email) {
        try {
            console.log('Tentative d\'inscription pour:', username);

            // Validation des entrées
            if (!username || !password || !email) {
                throw new Error('Tous les champs sont requis');
            }

            if (password.length < 8) {
                throw new Error('Le mot de passe doit contenir au moins 8 caractères');
            }

            if (!email.includes('@')) {
                throw new Error('Email invalide');
            }

            // Vérifier si l'utilisateur existe déjà
            const existingUser = await db.getUser(username);
            if (existingUser) {
                throw new Error('Cet utilisateur existe déjà');
            }

            // Hasher le mot de passe
            const hashedPassword = await bcrypt.hash(password, 10);

            // Créer l'utilisateur
            const userId = await db.createUser(username, hashedPassword, email);
            console.log('Utilisateur créé avec l\'ID:', userId);

            // Générer le token JWT
            const token = this.generateToken(userId, username);
            console.log('Token généré pour:', username);

            return {
                token,
                userId,
                username,
                email,
                role: 'user'
            };
        } catch (error) {
            console.error('Erreur lors de l\'inscription:', error);
            throw error;
        }
    }

    async login(username, password) {
        try {
            console.log('Tentative de connexion pour:', username);

            // Validation des entrées
            if (!username || !password) {
                throw new Error('Nom d\'utilisateur et mot de passe requis');
            }

            // Récupérer l'utilisateur
            const user = await db.getUser(username);
            if (!user) {
                throw new Error('Utilisateur non trouvé');
            }

            // Vérifier le mot de passe
            const validPassword = await bcrypt.compare(password, user.password);
            if (!validPassword) {
                throw new Error('Mot de passe incorrect');
            }

            // Générer le token JWT
            const token = this.generateToken(user.id, user.username);
            console.log('Token généré pour:', username);

            return {
                token,
                userId: user.id,
                username: user.username,
                email: user.email,
                role: user.role
            };
        } catch (error) {
            console.error('Erreur lors de la connexion:', error);
            throw error;
        }
    }

    generateToken(userId, username) {
        const payload = {
            userId,
            username,
            iat: Math.floor(Date.now() / 1000)
        };
        console.log('Génération du token avec payload:', payload);
        return jwt.sign(payload, this.secret, { expiresIn: '24h' });
    }

    verifyToken(token) {
        try {
            console.log('Vérification du token...');
            if (!token) {
                throw new Error('Token manquant');
            }
            const decoded = jwt.verify(token, this.secret);
            console.log('Token décodé:', decoded);
            return decoded;
        } catch (error) {
            console.error('Erreur de vérification du token:', error);
            if (error.name === 'TokenExpiredError') {
                throw new Error('Token expiré');
            }
            throw new Error('Token invalide');
        }
    }

    authenticate(req, res, next) {
        try {
            console.log('Vérification de l\'authentification...');
            const authHeader = req.headers.authorization;
            console.log('En-tête d\'autorisation:', authHeader);

            if (!authHeader) {
                console.log('En-tête d\'autorisation manquant');
                return res.status(401).json({
                    message: 'Token manquant',
                    code: 'AUTH_NO_TOKEN'
                });
            }

            const [bearer, token] = authHeader.split(' ');
            if (bearer !== 'Bearer' || !token) {
                console.log('Format de token invalide');
                return res.status(401).json({
                    message: 'Format de token invalide',
                    code: 'AUTH_INVALID_FORMAT'
                });
            }

            try {
                const decoded = this.verifyToken(token);
                console.log('Token vérifié avec succès');

                // Vérifier si l'utilisateur existe toujours
                db.getUser(decoded.username)
                    .then(user => {
                        if (!user) {
                            console.log('Utilisateur non trouvé');
                            return res.status(401).json({
                                message: 'Utilisateur non trouvé',
                                code: 'AUTH_USER_NOT_FOUND'
                            });
                        }
                        req.user = decoded;
                        next();
                    })
                    .catch(error => {
                        console.error('Erreur lors de la vérification de l\'utilisateur:', error);
                        return res.status(500).json({
                            message: 'Erreur serveur',
                            code: 'AUTH_SERVER_ERROR'
                        });
                    });
            } catch (error) {
                console.error('Erreur de vérification du token:', error);
                if (error.name === 'TokenExpiredError') {
                    return res.status(401).json({
                        message: 'Token expiré',
                        code: 'AUTH_TOKEN_EXPIRED'
                    });
                }
                return res.status(401).json({
                    message: 'Token invalide',
                    code: 'AUTH_INVALID_TOKEN'
                });
            }
        } catch (error) {
            console.error('Erreur d\'authentification:', error);
            return res.status(401).json({
                message: 'Non autorisé',
                code: 'AUTH_ERROR'
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