import { Router } from 'express';
import authRoutes from './authRoutes';

const router = Router();

router.use('/auth', authRoutes);

// add more route groups in future: /users, /admin, /restaurants ...

router.get('/', (_req, res) => {
  res.json({ ok: true, message: 'API is running' });
});

export default router;