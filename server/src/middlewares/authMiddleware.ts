import { Request, Response, NextFunction } from 'express';
import ApiError from '../utils/apiError';
import { verifyAccessToken } from '../helpers/tokenhelper';
const models = require('../models');

// Interface describing what fields we expect inside the decoded JWT payload
interface TokenPayload {
  id?: string;
  email?: string;
  role?: string;
  iat?: number; // creation time  (from JWT)
  exp?: number; // expiration time (from JWT)
}

// check authentication for protected route
export const authMiddleware = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return next(new ApiError(401, 'Authorization token missing'));
    }

    const token = authHeader.split(' ')[1]; //select token only after `Bearer<space/>`
    let payload: TokenPayload;
    try {
      payload = verifyAccessToken(token) as TokenPayload;
    } catch (err) {
      return next(new ApiError(401, 'Invalid or expired token'));
    }

    if (!payload?.id) {
      return next(new ApiError(401, 'Invalid token payload'));
    }

    // attach user object (from DB)
    const User = models.User;
    const user = await User.findByPk(payload.id, { attributes: { exclude: ['password'] } });
    if (!user) {
      return next(new ApiError(401, 'User not found'));
    }

    // Attach the user object to request (so next middlewares/controllers can access it)
    (req as any).user = user;
    next();
  } catch (err) {
    res.json("message: authMiddleware failed ")
    next(err);
  }
};