const express = require('express');
const AuthController = require('../controllers/authController');
const AuthValidator = require('../validators/authValidator');
const auth = require('../auth');

const router = express.Router();

// Route d'inscription
router.post('/register',
    AuthValidator.validateRegistration(),
    AuthValidator.handleValidationErrors,
    AuthController.register
);

// Route de connexion
router.post('/login',
    AuthValidator.validateLogin(),
    AuthValidator.handleValidationErrors,
    AuthController.login
);

// Route de déconnexion (nécessite une authentification)
router.post('/logout',
    auth.authenticate,
    AuthController.logout
);

// Route de rafraîchissement de token
router.post('/refresh',
    AuthController.refreshToken
);

// Route de vérification de token
router.get('/verify',
    AuthController.verifyToken
);

// Route pour changer le mot de passe (nécessite une authentification)
router.post('/change-password',
    auth.authenticate,
    AuthController.changePassword
);

// Route pour obtenir le profil utilisateur (nécessite une authentification)
router.get('/profile',
    auth.authenticate,
    AuthController.getProfile
);

// Routes d'administration (nécessitent le rôle admin)
router.get('/users',
    auth.authenticate,
    auth.requireRole('admin'),
    AuthController.getAllUsers
);

router.delete('/users/:userId',
    auth.authenticate,
    auth.requireRole('admin'),
    AuthController.deleteUser
);

module.exports = router; 