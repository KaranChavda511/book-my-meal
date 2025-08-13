import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET || 'secret';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';

// asign jwt token
export const signAccessToken = (payload: object) => {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN  as jwt.SignOptions['expiresIn']});
};

// verify token
export const verifyAccessToken = (token: string) => {
  return jwt.verify(token, JWT_SECRET);
};

