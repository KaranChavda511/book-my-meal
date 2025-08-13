import { Router } from 'express';
import { register, login, refreshToken, logout, forgotPassword, resetPassword } from '../controllers/authControllers';
import { validationMiddleware } from '../middlewares/validationMiddleware';
import { registerSchema, loginSchema, forgotPasswordSchema, resetPasswordSchema } from '../validations/authValidation';

const router = Router();

router.post('/register', validationMiddleware(registerSchema), register);
router.post('/login', validationMiddleware(loginSchema), login);
router.post('/refresh-token', refreshToken);
router.post('/logout', logout);
router.post('/forgot-password', validationMiddleware(forgotPasswordSchema), forgotPassword);
router.post('/reset-password', validationMiddleware(resetPasswordSchema), resetPassword);

export default router;

