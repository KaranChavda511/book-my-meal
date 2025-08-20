import { Request, Response, NextFunction } from 'express';
import * as userRepo from '../repositories/userRepository';
import ApiError from '../utils/apiError';

export const getProfile = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as any).user;
    if (!user) return next(new ApiError(401, 'Unauthorized'));
    res.json({ status: 'success', data: user });
  } catch (err) {
    next(err);
  }
};

export const updateProfile = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as any).user;
    if (!user) return next(new ApiError(401, 'Unauthorized'));

    const allowed = ['firstName', 'lastName', 'phone'];
    const updates: any = {};
    for (const key of allowed) {
      if (req.body[key] !== undefined) updates[key] = req.body[key];
    }

    const updated = await userRepo.updateUser(user.id, updates);
    res.json({ status: 'success', data: updated });
  } catch (err) {
    next(err);
  }
};

export const deleteAccount = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = (req as any).user;
    if (!user) return next(new ApiError(401, 'Unauthorized'));

    await userRepo.deleteUser(user.id);
    res.json({ status: 'success', message: 'Account deleted' });
  } catch (err) {
    next(err);
  }
};