import { Request, Response, NextFunction } from 'express';
import { ObjectSchema } from 'joi';
import ApiError from '../utils/apiError';


export const validationMiddleware = (schema: ObjectSchema) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const { error, value } = schema.validate( 
      // req.body,
      { body: req.body, query: req.query, params: req.params },
      { abortEarly: false, allowUnknown: true, stripUnknown: true }
    );

    if (error) {
      const details = error.details.map((d) => d.message);
      return next(new ApiError(400, 'Validation error', { details }));
    }

    next();
  };
};

