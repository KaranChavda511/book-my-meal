import { Router } from 'express';
import authRoutes from './authRoutes';

const router = Router();

router.get('/', (_req, res) => {
  res.json({ ok: true, message: 'API is running' });
});


router.use('/auth', authRoutes);



export default router;