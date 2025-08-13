import Joi from 'joi';

// Registration schema
export const registerSchema = Joi.object({
  body: Joi.object({
    firstName: Joi.string().min(2).max(50).required(),
    lastName: Joi.string().allow('').optional(),
    email: Joi.string().email().required(),
    password: Joi.string().min(8).max(128).required(),
    phone: Joi.string().allow('').optional()
  }),
  query: Joi.object({}),  // if you expect query params, define here or allow empty
  params: Joi.object({})  // if you expect route params, define here or allow empty
});

// Login schema
export const loginSchema = Joi.object({
  body: Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
  }),
  query: Joi.object({}),
  params: Joi.object({})
});


// Forgot password
export const forgotPasswordSchema = Joi.object({
  email: Joi.string().email().required()
});

// Reset password
export const resetPasswordSchema = Joi.object({
  token: Joi.string().required(),
  newPassword: Joi.string().min(8).max(128).required()
});