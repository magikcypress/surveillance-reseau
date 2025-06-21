class ErrorHandler {
    static handle(error, req, res, next) {
        console.error('Error:', error);

        // Erreurs de validation
        if (error.name === 'ValidationError') {
            return res.status(400).json({
                success: false,
                message: 'Données invalides',
                errors: Object.values(error.errors).map(err => ({
                    field: err.path,
                    message: err.message
                }))
            });
        }

        // Erreurs JWT
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({
                success: false,
                message: 'Token invalide',
                code: 'INVALID_TOKEN'
            });
        }

        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                success: false,
                message: 'Token expiré',
                code: 'TOKEN_EXPIRED'
            });
        }

        // Erreurs de base de données
        if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
            return res.status(409).json({
                success: false,
                message: 'Un utilisateur avec ces informations existe déjà',
                code: 'DUPLICATE_ENTRY'
            });
        }

        // Erreurs d'authentification
        if (error.message === 'Invalid credentials') {
            return res.status(401).json({
                success: false,
                message: 'Nom d\'utilisateur ou mot de passe incorrect',
                code: 'INVALID_CREDENTIALS'
            });
        }

        if (error.message === 'User not found') {
            return res.status(404).json({
                success: false,
                message: 'Utilisateur non trouvé',
                code: 'USER_NOT_FOUND'
            });
        }

        // Erreur par défaut
        return res.status(500).json({
            success: false,
            message: 'Erreur interne du serveur',
            code: 'INTERNAL_ERROR'
        });
    }

    static createError(message, statusCode = 500, code = null) {
        const error = new Error(message);
        error.statusCode = statusCode;
        error.code = code;
        return error;
    }
}

module.exports = ErrorHandler; 