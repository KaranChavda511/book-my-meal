import { Router } from 'express';
import { register, login, refreshToken, logout, forgotPassword, resetPassword } from '../controllers/authControllers';
import { validationMiddleware } from '../middlewares/validationMiddleware';
import { registerSchema, loginSchema, forgotPasswordSchema, resetPasswordSchema, refreshSchema } from '../helpers/validations/authValidation';

const router = Router();

// auth routes 
router.post('/register', validationMiddleware(registerSchema), register);
router.post('/login', validationMiddleware(loginSchema), login);


router.post('/refresh-token', validationMiddleware(refreshSchema), refreshToken);
router.post('/logout', logout);

router.post('/forgot-password', validationMiddleware(forgotPasswordSchema), forgotPassword);
router.post('/reset-password', validationMiddleware(resetPasswordSchema), resetPassword);

export default router;

