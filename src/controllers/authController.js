const auth = require('../auth');
const AuthValidator = require('../validators/authValidator');
const ErrorHandler = require('../utils/errorHandler');

class AuthController {
    /**
     * Enregistrer un nouvel utilisateur
     */
    static async register(req, res, next) {
        try {
            const result = await auth.register(req.body);
            res.status(201).json(result);
        } catch (error) {
            next(error);
        }
    }

    /**
     * Connecter un utilisateur
     */
    static async login(req, res, next) {
        try {
            const result = await auth.login(req.body);
            res.json(result);
        } catch (error) {
            next(error);
        }
    }

    /**
     * Déconnecter un utilisateur
     */
    static async logout(req, res, next) {
        try {
            const result = await auth.logout(req.user.id);
            res.json(result);
        } catch (error) {
            next(error);
        }
    }

    /**
     * Rafraîchir un token
     */
    static async refreshToken(req, res, next) {
        try {
            const { refreshToken } = req.body;
            if (!refreshToken) {
                return res.status(400).json({
                    success: false,
                    message: 'Token de rafraîchissement requis',
                    code: 'REFRESH_TOKEN_REQUIRED'
                });
            }

            const result = await auth.refreshToken(refreshToken);
            res.json(result);
        } catch (error) {
            next(error);
        }
    }

    /**
     * Vérifier un token
     */
    static async verifyToken(req, res, next) {
        try {
            const authHeader = req.headers.authorization;
            if (!authHeader) {
                return res.status(401).json({
                    success: false,
                    message: 'Token manquant',
                    code: 'TOKEN_MISSING'
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

            const user = await auth.verifyToken(token);
            res.json({
                success: true,
                message: 'Token valide',
                data: { user }
            });
        } catch (error) {
            next(error);
        }
    }

    /**
     * Changer le mot de passe
     */
    static async changePassword(req, res, next) {
        try {
            const { currentPassword, newPassword } = req.body;

            if (!currentPassword || !newPassword) {
                return res.status(400).json({
                    success: false,
                    message: 'Mot de passe actuel et nouveau mot de passe requis',
                    code: 'PASSWORDS_REQUIRED'
                });
            }

            const result = await auth.changePassword(req.user.id, currentPassword, newPassword);
            res.json(result);
        } catch (error) {
            next(error);
        }
    }

    /**
     * Obtenir le profil de l'utilisateur connecté
     */
    static async getProfile(req, res, next) {
        try {
            res.json({
                success: true,
                message: 'Profil récupéré avec succès',
                data: { user: req.user }
            });
        } catch (error) {
            next(error);
        }
    }

    /**
     * Obtenir tous les utilisateurs (administration)
     */
    static async getAllUsers(req, res, next) {
        try {
            const result = await auth.getAllUsers();
            res.json(result);
        } catch (error) {
            next(error);
        }
    }

    /**
     * Supprimer un utilisateur (administration)
     */
    static async deleteUser(req, res, next) {
        try {
            const { userId } = req.params;
            const result = await auth.deleteUser(parseInt(userId), req.user.id);
            res.json(result);
        } catch (error) {
            next(error);
        }
    }
}

module.exports = AuthController; 