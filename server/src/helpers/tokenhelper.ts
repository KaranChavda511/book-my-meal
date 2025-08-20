import jwt, { SignOptions, Secret } from 'jsonwebtoken';
import dotenv from 'dotenv';
dotenv.config();

// env variables with fallback
const ACCESS_SECRET: Secret = process.env.JWT_SECRET || 'access_secret';
const ACCESS_EXPIRES = (process.env.JWT_EXPIRES_IN || '24h') as SignOptions['expiresIn'];
const REFRESH_SECRET: Secret = process.env.REFRESH_TOKEN_SECRET || 'refresh_secret';
const REFRESH_EXPIRES = (process.env.REFRESH_TOKEN_EXPIRES_IN || '7d') as SignOptions['expiresIn'];

// assign jwt access token
export const signAccessToken = (payload: object): string => {
  return jwt.sign(payload, ACCESS_SECRET, { expiresIn: ACCESS_EXPIRES });
};

// verify access token
export const verifyAccessToken = (token: string) => {
  return jwt.verify(token, ACCESS_SECRET);
};

// assign jwt refresh token
export const signRefreshToken = (payload: object): string => {
  return jwt.sign(payload, REFRESH_SECRET, { expiresIn: REFRESH_EXPIRES });
};

// verify refresh token
export const verifyRefreshToken = (token: string) => {
  return jwt.verify(token, REFRESH_SECRET);
};

// Helper to compute refresh token expiry date object
export const getRefreshTokenExpiry = (): Date => {
  const val = String(REFRESH_EXPIRES).toLowerCase();
  const now = new Date();
  const match = val.match(/^(\d+)(d|h|m|s)$/);
  if (!match) {
    now.setDate(now.getDate() + 7);
    return now;
  }
  const n = parseInt(match[1], 10);
  const unit = match[2];
  switch (unit) {
    case 'd':
      now.setDate(now.getDate() + n);
      break;
    case 'h':
      now.setHours(now.getHours() + n);
      break;
    case 'm':
      now.setMinutes(now.getMinutes() + n);
      break;
    case 's':
      now.setSeconds(now.getSeconds() + n);
      break;
    default:
      now.setDate(now.getDate() + 7);
  }
  return now;
};
