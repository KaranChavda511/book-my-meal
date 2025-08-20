import { Router } from 'express';
import authRoutes from './authRoutes';
import userRoutes from './userRoutes'

const router = Router();


router.get('/', (_req, res) => {
  res.json({ ok: true, message: 'API is running' });
});


router.use('/auth', authRoutes);
router.use('/users', userRoutes);



export default router;