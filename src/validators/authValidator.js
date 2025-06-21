const { body, validationResult } = require('express-validator');

class AuthValidator {
    static validateRegistration() {
        return [
            body('username')
                .trim()
                .isLength({ min: 3, max: 30 })
                .withMessage('Le nom d\'utilisateur doit contenir entre 3 et 30 caractères')
                .matches(/^[a-zA-Z0-9_-]+$/)
                .withMessage('Le nom d\'utilisateur ne peut contenir que des lettres, chiffres, tirets et underscores'),

            body('password')
                .isLength({ min: 8 })
                .withMessage('Le mot de passe doit contenir au moins 8 caractères')
                .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
                .withMessage('Le mot de passe doit contenir au moins une minuscule, une majuscule et un chiffre'),

            body('confirmPassword')
                .custom((value, { req }) => {
                    if (value !== req.body.password) {
                        throw new Error('Les mots de passe ne correspondent pas');
                    }
                    return true;
                }),

            body('email')
                .optional()
                .isEmail()
                .withMessage('Format d\'email invalide')
        ];
    }

    static validateLogin() {
        return [
            body('username')
                .trim()
                .notEmpty()
                .withMessage('Le nom d\'utilisateur est requis'),

            body('password')
                .notEmpty()
                .withMessage('Le mot de passe est requis')
        ];
    }

    static handleValidationErrors(req, res, next) {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: 'Données invalides',
                errors: errors.array().map(error => ({
                    field: error.path,
                    message: error.msg
                }))
            });
        }
        next();
    }
}

module.exports = AuthValidator; 