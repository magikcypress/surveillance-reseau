const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const Database = require('./database');
const ErrorHandler = require('./utils/errorHandler');

class Auth {
    constructor() {
        this.db = new Database();
        this.jwtSecret = process.env.JWT_SECRET || 'your-secret-key';
        this.tokenExpiry = process.env.JWT_EXPIRY || '24h';
        this.refreshTokenExpiry = process.env.REFRESH_TOKEN_EXPIRY || '7d';

        if (!process.env.JWT_SECRET) {
            console.warn('⚠️  JWT_SECRET is not set. Using default secret key.');
        }

        // Lier les méthodes à l'instance
        this.authenticate = this.authenticate.bind(this);
        this.verifyToken = this.verifyToken.bind(this);
    }

    /**
     * Enregistrer un nouvel utilisateur
     * @param {Object} userData - Données de l'utilisateur
     * @returns {Object} Utilisateur créé avec token
     */
    async register(userData) {
        try {
            // Vérifier si l'utilisateur existe déjà
            const existingUser = await this.db.getUserByUsername(userData.username);
            if (existingUser) {
                throw ErrorHandler.createError('Un utilisateur avec ce nom existe déjà', 409, 'USERNAME_EXISTS');
            }

            // Vérifier si l'email existe déjà (si fourni)
            if (userData.email) {
                const existingEmail = await this.db.getUserByEmail(userData.email);
                if (existingEmail) {
                    throw ErrorHandler.createError('Un utilisateur avec cet email existe déjà', 409, 'EMAIL_EXISTS');
                }
            }

            // Hasher le mot de passe
            const saltRounds = 12;
            const hashedPassword = await bcrypt.hash(userData.password, saltRounds);

            // Créer l'utilisateur
            const email = userData.email || `${userData.username}@example.com`;
            const userId = await this.db.createUser(userData.username, hashedPassword, email);

            // Récupérer l'utilisateur créé
            const user = await this.db.getUserByUsername(userData.username);

            // Générer les tokens
            const { accessToken, refreshToken } = this.generateTokens(user);

            return {
                success: true,
                message: 'Inscription réussie',
                data: {
                    user: this.sanitizeUser(user),
                    accessToken,
                    refreshToken
                }
            };
        } catch (error) {
            throw error;
        }
    }

    /**
     * Connecter un utilisateur
     * @param {Object} credentials - Identifiants de connexion
     * @returns {Object} Utilisateur connecté avec token
     */
    async login(credentials) {
        try {
            // Vérifier les identifiants
            const user = await this.db.getUserByUsername(credentials.username);
            if (!user) {
                throw ErrorHandler.createError('Nom d\'utilisateur ou mot de passe incorrect', 401, 'INVALID_CREDENTIALS');
            }

            // Vérifier le mot de passe
            const isValid = await bcrypt.compare(credentials.password, user.password);
            if (!isValid) {
                throw ErrorHandler.createError('Nom d\'utilisateur ou mot de passe incorrect', 401, 'INVALID_CREDENTIALS');
            }

            // Mettre à jour la dernière connexion
            await this.db.updateLastLogin(user.id);

            // Générer les tokens
            const { accessToken, refreshToken } = this.generateTokens(user);

            return {
                success: true,
                message: 'Connexion réussie',
                data: {
                    user: this.sanitizeUser(user),
                    accessToken,
                    refreshToken
                }
            };
        } catch (error) {
            throw error;
        }
    }

    /**
     * Déconnecter un utilisateur
     * @param {string} userId - ID de l'utilisateur
     * @returns {Object} Résultat de la déconnexion
     */
    async logout(userId) {
        try {
            // Dans une implémentation plus avancée, on pourrait invalider le refresh token
            // ou l'ajouter à une liste noire
            await this.db.updateLastLogout(userId);

            return {
                success: true,
                message: 'Déconnexion réussie'
            };
        } catch (error) {
            throw error;
        }
    }

    /**
     * Rafraîchir un token
     * @param {string} refreshToken - Token de rafraîchissement
     * @returns {Object} Nouveaux tokens
     */
    async refreshToken(refreshToken) {
        try {
            const decoded = jwt.verify(refreshToken, this.jwtSecret);
            const user = await this.db.getUserById(decoded.id);

            if (!user) {
                throw ErrorHandler.createError('Utilisateur non trouvé', 404, 'USER_NOT_FOUND');
            }

            const tokens = this.generateTokens(user);

            return {
                success: true,
                message: 'Token rafraîchi avec succès',
                data: {
                    user: this.sanitizeUser(user),
                    accessToken: tokens.accessToken,
                    refreshToken: tokens.refreshToken
                }
            };
        } catch (error) {
            if (error.name === 'TokenExpiredError') {
                throw ErrorHandler.createError('Token de rafraîchissement expiré', 401, 'REFRESH_TOKEN_EXPIRED');
            }
            throw error;
        }
    }

    /**
     * Générer les tokens d'accès et de rafraîchissement
     * @param {Object} user - Utilisateur
     * @returns {Object} Tokens générés
     */
    generateTokens(user) {
        const payload = {
            id: user.id,
            username: user.username,
            role: user.role
        };

        const accessToken = jwt.sign(payload, this.jwtSecret, {
            expiresIn: this.tokenExpiry
        });

        const refreshToken = jwt.sign(payload, this.jwtSecret, {
            expiresIn: this.refreshTokenExpiry
        });

        return { accessToken, refreshToken };
    }

    /**
     * Vérifier un token d'accès
     * @param {string} token - Token à vérifier
     * @returns {Object} Données décodées du token
     */
    async verifyToken(token) {
        try {
            const decoded = jwt.verify(token, this.jwtSecret);
            const user = await this.db.getUserById(decoded.id);

            if (!user) {
                throw ErrorHandler.createError('Utilisateur non trouvé', 404, 'USER_NOT_FOUND');
            }

            return this.sanitizeUser(user);
        } catch (error) {
            if (error.name === 'TokenExpiredError') {
                throw ErrorHandler.createError('Token expiré', 401, 'TOKEN_EXPIRED');
            }
            if (error.name === 'JsonWebTokenError') {
                throw ErrorHandler.createError('Token invalide', 401, 'INVALID_TOKEN');
            }
            throw error;
        }
    }

    /**
     * Middleware d'authentification
     */
    async authenticate(req, res, next) {
        try {
            const authHeader = req.headers.authorization;
            if (!authHeader) {
                return res.status(401).json({
                    success: false,
                    message: 'Token d\'accès requis',
                    code: 'ACCESS_TOKEN_REQUIRED'
                });
            }

            const [bearer, token] = authHeader.split(' ');
            if (bearer !== 'Bearer' || !token) {
                return res.status(401).json({
                    success: false,
                    message: 'Format de token invalide',
                    code: 'INVALID_TOKEN_FORMAT'
                });
            }

            const user = await this.verifyToken(token);
            req.user = user;
            next();
        } catch (error) {
            return res.status(401).json({
                success: false,
                message: error.message,
                code: error.code || 'AUTHENTICATION_FAILED'
            });
        }
    }

    /**
     * Middleware de vérification de rôle
     * @param {string|Array} roles - Rôle(s) autorisé(s)
     */
    requireRole(roles) {
        return async (req, res, next) => {
            try {
                const allowedRoles = Array.isArray(roles) ? roles : [roles];

                if (!req.user) {
                    return res.status(401).json({
                        success: false,
                        message: 'Authentification requise',
                        code: 'AUTHENTICATION_REQUIRED'
                    });
                }

                if (!allowedRoles.includes(req.user.role)) {
                    return res.status(403).json({
                        success: false,
                        message: 'Accès refusé - Permissions insuffisantes',
                        code: 'INSUFFICIENT_PERMISSIONS'
                    });
                }

                next();
            } catch (error) {
                return res.status(500).json({
                    success: false,
                    message: 'Erreur lors de la vérification des permissions',
                    code: 'PERMISSION_CHECK_ERROR'
                });
            }
        };
    }

    /**
     * Nettoyer les données utilisateur (supprimer les informations sensibles)
     * @param {Object} user - Utilisateur
     * @returns {Object} Utilisateur nettoyé
     */
    sanitizeUser(user) {
        const { password, ...sanitizedUser } = user;
        return sanitizedUser;
    }

    /**
     * Changer le mot de passe d'un utilisateur
     * @param {number} userId - ID de l'utilisateur
     * @param {string} currentPassword - Mot de passe actuel
     * @param {string} newPassword - Nouveau mot de passe
     */
    async changePassword(userId, currentPassword, newPassword) {
        try {
            const user = await this.db.getUserById(userId);
            if (!user) {
                throw ErrorHandler.createError('Utilisateur non trouvé', 404, 'USER_NOT_FOUND');
            }

            // Vérifier le mot de passe actuel
            const isValid = await bcrypt.compare(currentPassword, user.password);
            if (!isValid) {
                throw ErrorHandler.createError('Mot de passe actuel incorrect', 401, 'INVALID_CURRENT_PASSWORD');
            }

            // Hasher le nouveau mot de passe
            const saltRounds = 12;
            const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);

            // Mettre à jour le mot de passe
            await this.db.updatePassword(userId, hashedNewPassword);

            return {
                success: true,
                message: 'Mot de passe modifié avec succès'
            };
        } catch (error) {
            throw error;
        }
    }

    /**
     * Supprimer un utilisateur
     * @param {number} userId - ID de l'utilisateur à supprimer
     * @param {number} currentUserId - ID de l'utilisateur qui effectue la suppression
     */
    async deleteUser(userId, currentUserId) {
        try {
            // Vérifier que l'utilisateur existe
            const user = await this.db.getUserById(userId);
            if (!user) {
                throw ErrorHandler.createError('Utilisateur non trouvé', 404, 'USER_NOT_FOUND');
            }

            // Empêcher la suppression de soi-même
            if (userId === currentUserId) {
                throw ErrorHandler.createError('Vous ne pouvez pas supprimer votre propre compte', 400, 'CANNOT_DELETE_SELF');
            }

            // Empêcher la suppression du dernier administrateur
            if (user.role === 'admin') {
                const allUsers = await this.db.getAllUsers();
                const adminUsers = allUsers.filter(u => u.role === 'admin' && u.is_active);
                if (adminUsers.length <= 1) {
                    throw ErrorHandler.createError('Impossible de supprimer le dernier administrateur', 400, 'CANNOT_DELETE_LAST_ADMIN');
                }
            }

            // Supprimer l'utilisateur
            const deleted = await this.db.deleteUser(userId);
            if (!deleted) {
                throw ErrorHandler.createError('Erreur lors de la suppression de l\'utilisateur', 500, 'DELETE_FAILED');
            }

            return {
                success: true,
                message: 'Utilisateur supprimé avec succès'
            };
        } catch (error) {
            throw error;
        }
    }

    /**
     * Obtenir tous les utilisateurs (pour l'administration)
     */
    async getAllUsers() {
        try {
            const users = await this.db.getAllUsers();
            return {
                success: true,
                message: 'Utilisateurs récupérés avec succès',
                data: { users }
            };
        } catch (error) {
            throw error;
        }
    }
}

// Exporter une instance de la classe Auth
const auth = new Auth();
module.exports = auth; 