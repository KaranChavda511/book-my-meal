import { Router } from 'express';
import { authMiddleware } from '../middlewares/authMiddleware';
import { getProfile, updateProfile, deleteAccount } from '../controllers/userController';
import { validationMiddleware } from '../middlewares/validationMiddleware';
import { updateProfileSchema } from '../helpers/validations/authValidation';

const router = Router();

router.get('/profile', authMiddleware, getProfile);
router.put('/profile', authMiddleware, validationMiddleware(updateProfileSchema), updateProfile);
router.delete('/account', authMiddleware, deleteAccount);

export default router;