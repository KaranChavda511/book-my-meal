import { Router } from 'express';
import { authMiddleware } from '../middlewares/authMiddleware';
import { getProfile, updateProfile, deleteAccount } from '../controllers/userController';
import { validationMiddleware } from '../middlewares/validationMiddleware';
import { updateProfileSchema } from '../helpers/validations/authValidation';
import { authorizeRoles } from '../middlewares/roleMiddleware';

const router = Router();

router.get('/profile', authMiddleware, authorizeRoles("admin", "user"), getProfile);
router.put('/profile', authMiddleware, authorizeRoles("user"), validationMiddleware(updateProfileSchema), updateProfile);
router.delete('/account', authMiddleware, authorizeRoles("admin", "user"), deleteAccount);

export default router;
