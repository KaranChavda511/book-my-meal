import { Request, Response, NextFunction } from 'express';
import * as authService from '../services/authService';
import ApiError from '../utils/apiError';

export const register = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const result = await authService.registerUser(req.body);
    res.status(201).json({ status: 'success', data: result });
  } catch (err) {
    next(err);
  }
};

export const login = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const result = await authService.loginUser(req.body);
    res.status(200).json({ status: 'success', data: result });
  } catch (err) {
    next(err);
  }
};

export const refreshToken = async (_req: Request, _res: Response, next: NextFunction) => {
  // placeholder - implement refresh token flow
  next(new ApiError(501, 'Not implemented'));
};

export const logout = async (_req: Request, _res: Response, next: NextFunction) => {
  // placeholder - implement logout (token blacklist or client-side delete)
  next(new ApiError(501, 'Not implemented'));
};

export const forgotPassword = async (_req: Request, _res: Response, next: NextFunction) => {
  // placeholder - implement send reset token by email
  next(new ApiError(501, 'Not implemented'));
};

export const resetPassword = async (_req: Request, _res: Response, next: NextFunction) => {
  // placeholder - implement reset password using token
  next(new ApiError(501, 'Not implemented'));
};