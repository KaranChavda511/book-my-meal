import { Request, Response, NextFunction } from 'express';
import ApiError from '../utils/apiError';

export const errorMiddleware = (err: any, _req: Request, res: Response, _next: NextFunction) => {
  if (err instanceof ApiError) {
    return res.status(err.statusCode).json({
      status: 'error',
      message: err.message,
      ...(err.details ? { details: err.details } : {})
    });
  }

  // For Sequelize validation errors etc, you can introspect err.name
  // eslint-disable-next-line no-console
  console.error(err);

  res.status(500).json({
    status: 'error',
    message: 'Internal Server Error'
  });
};