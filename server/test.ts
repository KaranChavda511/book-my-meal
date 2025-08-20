/** models/user.js */
"use strict";
const { Model } = require("sequelize");

module.exports = (sequelize, DataTypes) => {
  // here define associations
  class User extends Model {
    static associate(models) {
      if (models.Session) {
        User.hasMany(models.Session, { foreignKey: "userId", as: "sessions" });
      } // referes user has many sessions
    }
  }

  // User Table Schema
  User.init(
    {
      firstName: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      lastName: {
        type: DataTypes.STRING,
      },
      email: {
        type: DataTypes.STRING,
        unique: true,
        allowNull: false,
        validate: { isEmail: true },
      },
      password: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      phone: {
        type: DataTypes.STRING,
      },
      role: {
        type: DataTypes.ENUM("user", "admin", "rider", "restaurant_admin"), 
        allowNull: false,
        defaultValue: "user",
      },
      isEmailVerified: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
      },
    },
    {
      sequelize, // connections
      modelName: "User", // model name
      tableName: "Users", // database table name
      underscored: false, // field names won't use snake_case
      timestamps: true, // auto add CreatedAt, updatedAt
    }
  );

  return User;
};

/** models/session.js */
'use strict';
const { Model } = require('sequelize');

module.exports = (sequelize, DataTypes) => {
  class Session extends Model {
    static associate(models) {
      // A session belongs to a user (User model)
      if (models.User) {
        Session.belongsTo(models.User, { foreignKey: 'userId', as: 'user' });
      }
    }
  }

  Session.init(
    {
      id: {
        type: DataTypes.UUID,
        primaryKey: true,
        defaultValue: DataTypes.UUIDV4
      },
      userId: {
        type: DataTypes.UUID,
        allowNull: false
      },
      refreshToken: {
        type: DataTypes.TEXT,
        allowNull: false
      },
      userAgent: { // meta data about client system
        type: DataTypes.STRING,
        allowNull: true
      },
      ip: {
        type: DataTypes.STRING,
        allowNull: true
      },
      expiresAt: {
        type: DataTypes.DATE,
        allowNull: false
      },
      revoked: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
      }
    },
    {
      sequelize,
      modelName: 'Session',
      tableName: 'Sessions',
      timestamps: true,
      underscored: false
    }
  );

  return Session;
};

/** models/passwordReset.js */
'use strict';
const { Model } = require('sequelize');

module.exports = (sequelize, DataTypes) => {
  class PasswordReset extends Model {
    static associate(models) {
      if (models.User) {
        PasswordReset.belongsTo(models.User, { foreignKey: 'userId', as: 'user' });
      }
    }
  }

  PasswordReset.init(
    {
      id: {
        type: DataTypes.UUID,
        primaryKey: true,
        defaultValue: DataTypes.UUIDV4
      },
      userId: {
        type: DataTypes.UUID,
        allowNull: false
      },
      token: {
        type: DataTypes.STRING(255),
        allowNull: false,
        unique: true
      },
      expiresAt: {
        type: DataTypes.DATE,
        allowNull: false
      },
      used: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
      }
    },
    {
      sequelize,
      modelName: 'PasswordReset',
      tableName: 'PasswordResets',
      timestamps: true
    }
  );

  return PasswordReset;
};





/**models/index.js */
'use strict';

const fs = require('fs');
const path = require('path');
const Sequelize = require('sequelize');
const basename = path.basename(__filename);
const env = process.env.NODE_ENV || 'development';
const config = require('../utils/sequelizeConfig.js')[env];

const db = {};
let sequelize;

// create sequelize instance
if (config.url) {
  sequelize = new Sequelize(config.url, config);
} else {
  sequelize = new Sequelize(config.database, config.username, config.password, config);
}

// Auto-load all models 
fs.readdirSync(__dirname)
  .filter(file => {
    return file.indexOf('.') !== 0 && file !== basename && file.slice(-3) === '.js';
  })
  .forEach(file => {
    const model = require(path.join(__dirname, file))(sequelize, Sequelize.DataTypes);
    db[model.name] = model;
  });

// Run model associations if defined
Object.keys(db).forEach(modelName => {
  if (db[modelName].associate) {
    db[modelName].associate(db);
  }
});

db.sequelize = sequelize;
db.Sequelize = Sequelize;

module.exports = db;


/** userRepository.ts */
const models = require('../models');
const { User } = models;

// create user in db
export const createUser = async (data: any) => {
  return User.create(data);
};

// find user by email in db
export const findUserByEmail = async (email: string) => {
  return User.findOne({ where: { email } });
};

// find user by id in db
export const findUserById = async (id: string) => {
  return User.findByPk(id);
};

// update user
export const updateUser = async (id: string, updates: any) => {
  const user = await findUserById(id);
  if (!user) return null;
  await user.update(updates);
  // remove password from returned object
  const JSONUser = user.toJSON();
  delete JSONUser.password;
  return JSONUser;
};

// delete user 
export const deleteUser = async (id: string) => {
  const user = await findUserById(id);
  if (!user) return null;
  return user.destroy();
};

// update user password
export const updateUserPassword = async (id: string, passwordHash: string) => {
  const user = await findUserById(id);
  if (!user) return null;
  await user.update({ password: passwordHash });
  const JSONUser = user.toJSON();
  delete JSONUser.password;
  return JSONUser;
};


/** sessionRepository.ts */
const models = require('../models');
const { Session } = models;

// create session 
export const createSession = async (data: {
  userId: string;
  refreshToken: string;
  userAgent?: string | null | undefined;
  ip?: string;
  expiresAt: Date;
}) => {
  return Session.create(data);
};

// find session by token
export const findSessionByToken = async (refreshToken: string) => {
  return Session.findOne({ where: { refreshToken } });
};

// find session by id
export const findSessionById = async (id: string) => {
  return Session.findByPk(id);
};

// revoke session by id (server-side session invalidation)
export const revokeSession = async (id: string) => {
  const session = await findSessionById(id);
  if (!session) return null;
  session.revoked = true;
  await session.save();
  return session;
};

// delete session by id
export const deleteSessionsByUser = async (userId: string) => {
  return Session.destroy({ where: { userId } });
};


/** passwordResetRepository.ts */
const models = require('../models');
const { PasswordReset } = models;

// Password Reset Token
export const createPasswordReset = async (data: {
  userId: string;
  token: string;
  expiresAt: Date;
}) => {
  return PasswordReset.create({ ...data, used: false });
};

// User Find by token
export const findByToken = async (token: string) => {
  return PasswordReset.findOne({ where: { token } });
};

// Token Marked as Used
export const markUsed = async (id: string) => {
  const rec = await PasswordReset.findByPk(id);
  if (!rec) return null;
  rec.used = true;
  await rec.save();
  return rec;
};


/** services/authService.ts */
import { createUser, findUserByEmail } from '../repositories/userRepository';
import { hashPassword, comparePassword } from '../helpers/passwordHelpers';
import { signAccessToken } from '../helpers/tokenhelper';
import ApiError from '../utils/apiError';

// register service 
export const registerUser = async (payload: any) => {
  const existing = await findUserByEmail(payload.email);
  if (existing) {
    throw new ApiError(400, 'Email already registered');
  }

  const hashed = await hashPassword(payload.password);
  const user = await createUser({
    firstName: payload.firstName,
    lastName: payload.lastName,
    email: payload.email,
    password: hashed,
    phone: payload.phone
  });

  // Do not return password
  const token = signAccessToken({ id: user.id, email: user.email, role: user.role });

  return { user: { id: user.id, firstName: user.firstName, email: user.email }, token };
};


// login service 
export const loginUser = async (payload: any) => {
  const user = await findUserByEmail(payload.email);
  if (!user) {
    throw new ApiError(401, 'Email is not exist , Please Register first.');
  }

  const isValid = await comparePassword(payload.password, user.password);
  if (!isValid) {
    throw new ApiError(401, 'Incorect Password, Try again !');
  }

  const token = signAccessToken({ id: user.id, email: user.email, role: user.role });

  return { user: { id: user.id, firstName: user.firstName, lastName: user.lastName, email: user.email }, token };
};



/** services/emailService.ts */
import nodemailer from 'nodemailer';

const host = process.env.SMTP_HOST;
const port = Number(process.env.SMTP_PORT );
const user = process.env.SMTP_USER;
const pass = process.env.SMTP_PASSWORD;
const fromEmail = process.env.FROM_EMAIL ;

if (!host || !user || !pass) {
  console.warn('[emailService] SMTP env vars missing. Emails will fail unless configured.');
}

const transporter = nodemailer.createTransport({
  host,
  port,
  secure: port === 465, // true for 465, false for 587/25
  auth: { user, pass }
});

export const sendMail = async (to: string, subject: string, html: string) => {
  return transporter.sendMail({
    from: fromEmail,
    to,
    subject,
    html
  });
};

export const sendPasswordResetEmail = async (to: string, resetLink: string) => {
  const subject = 'Reset your password';
  const html = `
    <div style="font-family:Arial,Helvetica,sans-serif;line-height:1.6;">
      <h2>Reset your password</h2>
      <p>We received a request to reset your password. Click the button below to set a new password.</p>
      <p>
        <a href="${resetLink}" style="display:inline-block;padding:10px 16px;border-radius:6px;background:#2563eb;color:#fff;text-decoration:none;">Reset Password</a>
      </p>
      <p>Or open this link: <br/><a href="${resetLink}">${resetLink}</a></p>
      <p>If you did not request this, you can ignore this email.</p>
    </div>
  `;
  return sendMail(to, subject, html);
};


/** middlewares/authMiddleware.ts */
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

    // if payload then it must contain id
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


/** helpers/tokenHelpers.ts */
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


/** controllers/authController.ts */
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



/** controllers/userController.ts */
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



/** routes/index.ts */
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



/** routes/authRoutes.ts */
import { Router } from 'express';
import { register, login, refreshToken, logout, forgotPassword, resetPassword } from '../controllers/authControllers';
import { validationMiddleware } from '../middlewares/validationMiddleware';
import { registerSchema, loginSchema, forgotPasswordSchema, resetPasswordSchema, refreshSchema } from '../helpers/validations/authValidation';

const router = Router();

// auth routes 
router.post('/register', validationMiddleware(registerSchema), register);
router.post('/login', validationMiddleware(loginSchema), login);


router.post('/refresh-token', validationMiddleware(refreshSchema), refreshToken);
router.post('/logout', logout);

router.post('/forgot-password', validationMiddleware(forgotPasswordSchema), forgotPassword);
router.post('/reset-password', validationMiddleware(resetPasswordSchema), resetPassword);

export default router;


/** routes/userRoutes.ts */
import { Router } from 'express';
import { authMiddleware } from '../middlewares/authMiddleware';
import { getProfile, updateProfile, deleteAccount } from '../controllers/userController';
import { validationMiddleware } from '../middlewares/validationMiddleware';
import { updateProfileSchema } from '../helpers/validations/authValidation';
import { authorizeRoles } from '../middlewares/roleMiddleware';

const router = Router();

router.get('/profile', authMiddleware, authorizeRoles("admin", "user"), getProfile);
router.put('/profile', authMiddleware, authorizeRoles("user"), validationMiddleware(updateProfileSchema), updateProfile);
router.delete('/account', authorizeRoles("admin", "user"), authMiddleware, deleteAccount);

export default router;







