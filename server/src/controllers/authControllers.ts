import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import ApiError from '../utils/apiError';
import * as authService from '../services/authService';
import * as sessionRepo from '../repositories/sessionRepository';
import * as prRepo from '../repositories/passwordResetRepository';
import { signRefreshToken, getRefreshTokenExpiry, signAccessToken, verifyRefreshToken } from '../helpers/tokenhelper';
import { buildResetLink } from '../helpers/templates/emailTemplates';
import { sendPasswordResetEmail } from '../services/emailService';
import { hashPassword } from '../helpers/passwordHelpers';
import { updateUserPassword, findUserByEmail } from '../repositories/userRepository';

// register controller  (with refresh token logic)
export const register = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const result = await authService.registerUser(req.body); // it has  {user, token} 
    // create refresh token & session
    const refreshToken = signRefreshToken({ id: result.user.id, email: result.user.email, role: 'user' });
    const expiresAt = getRefreshTokenExpiry();

    await sessionRepo.createSession({
      userId: result.user.id,
      refreshToken,
      userAgent: req.headers['user-agent'] || null,
      ip: req.ip,
      expiresAt
    });

    res.status(201).json({
      status: 'success',
      message: 'User Register Successfully',
      data: {
        user: result.user,
        accessToken: result.token,
        refreshToken
      }
    });

  } catch (err) {
    next(err);
  }
};


// login controller  (with refresh token logic)
export const login = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const result = await authService.loginUser(req.body);
    // create refresh token & session
    const refreshToken = signRefreshToken({ id: result.user.id, email: result.user.email, role: 'user' });
    const expiresAt = getRefreshTokenExpiry();

    await sessionRepo.createSession({
      userId: result.user.id,
      refreshToken,
      userAgent: req.headers['user-agent'] || null, // meta data about client system
      ip: req.ip,
      expiresAt
    });

    res.status(200).json({
      status: 'success',
      data: {
        user: result.user,
        accessToken: result.token,
        refreshToken
      }
    });
  } catch (err) {
    next(err);
  }
};


// controller for get new access token & refresh token 
export const refreshToken = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return next(new ApiError(400, 'Refresh token required'));

    // verify token signature & expiry
    let payload: any;
    try {
      // payload = require('../helpers/tokenHelper').verifyRefreshToken(refreshToken);
      payload = verifyRefreshToken(refreshToken);
    } catch (err) {
      return next(new ApiError(401, 'Invalid refresh token'));
    }

    // check session exists and is not revoked
    const session = await sessionRepo.findSessionByToken(refreshToken);
    if (!session || session.revoked) return next(new ApiError(401, 'Refresh token invalidated'));

    // Optionally check expiry in session.expiresAt vs now
    if (new Date(session.expiresAt) < new Date()) {
      return next(new ApiError(401, 'Refresh token expired'));
    }

    // sign new access token (and optionally new refresh token rotation)
    const accessToken = signAccessToken({ id: payload.id, email: payload.email, role: payload.role });

    res.json({ status: 'success', data: { accessToken } });
  } catch (err) {
    next(err);
  }
};


// controller for logout (even when jwt token is not expires)
export const logout = async (req: Request, res: Response, next: NextFunction) => {
  try {

    const { refreshToken } = req.body;
    if (!refreshToken) return next(new ApiError(400, 'Refresh token required'));

    const session = await sessionRepo.findSessionByToken(refreshToken);
    if (!session) return next(new ApiError(404, 'Session not found'));

    // session is already revoked 
    if (session.revoked) {
      return next(new ApiError(401, 'Session already revoked'));
    }

     if (session.expiresAt && new Date() > session.expiresAt) {
      return next(new ApiError(401, 'Session has expired'));
    }

    await sessionRepo.revokeSession(session.id); //Useful for banning users, logging out from all devices, or managing refresh tokens securely.

    res.json({ status: 'success', message: 'Logged out' });
  } catch (err) {
    next(err);
  }
};


// controller for forgot password request
export const forgotPassword = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email } = req.body;
    const user = await findUserByEmail(email);
    
    if (!user) return next(new ApiError(401, 'please register first'))

    // generate a cryptographically strong token
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    await prRepo.createPasswordReset({ userId: user.id, token, expiresAt });

    const link = buildResetLink(token);
    await sendPasswordResetEmail(user.email, link);

    res.json({ status: 'success', message: 'If that email exists, a reset link was sent.' });
  } catch (err) {
    next(err);
  }
};

// Controller for Reset password
export const resetPassword = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { token, newPassword } = req.body;

    const rec = await prRepo.findByToken(token);
    if (!rec || rec.used) return next(new ApiError(400, 'Invalid or used token'));
    if (new Date(rec.expiresAt) < new Date()) return next(new ApiError(400, 'Token expired'));

    const passwordHash = await hashPassword(newPassword);
    await updateUserPassword(rec.userId, passwordHash);

    // invalidate refresh sessions for this user
    await sessionRepo.deleteSessionsByUser(rec.userId);

    // mark token as used
    await prRepo.markUsed(rec.id);

    res.json({ status: 'success', message: 'Password has been reset successfully' });
  } catch (err) {
    next(err);
  }
};

