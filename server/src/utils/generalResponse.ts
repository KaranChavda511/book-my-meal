
import { Response } from 'express';


type ApiResponseData<T = any> = T | null;
type ApiErrorData = any[] | string | null;

interface MetaData {
  success: boolean;
  statusCode: number;
  message: string;
  error?: ApiErrorData;
}

interface ApiResponse<T = any> {
  data: ApiResponseData<T>;
  metaData: MetaData;
}

// Custom ApiError class
export class ApiError extends Error {
  public errors: any[];

  constructor(
    public statusCode: number,
    message = 'Something went wrong',
    errors: any[] = []
  ) {
    super(message);
    this.statusCode = statusCode;
    this.errors = errors;
    Error.captureStackTrace(this, this.constructor);
  }
}

// Centralized response sender
export function sendResponse<T>(
  res: Response,
  statusCode: number,
  message: string,
  data: ApiResponseData<T> = null,
  error: ApiErrorData = null
): Response<ApiResponse<T>> {
  const success = statusCode >= 200 && statusCode < 400;

  return res.status(statusCode).json({
    data: success ? data : null,
    metaData: {
      success,
      statusCode,
      message,
      ...(success ? {} : { error }),
    },
  });
}

// Utility functions for common responses
export const ResponseHelper = {
  success: <T>(
    res: Response,
    data: T,
    message = 'Success',
    statusCode = 200
  ) => sendResponse(res, statusCode, message, data),

  created: <T>(
    res: Response,
    data: T,
    message = 'Resource created'
  ) => sendResponse(res, 201, message, data),

  badRequest: (
    res: Response,
    message = 'Bad Request',
    errors: any[] = []
  ) => sendResponse(res, 400, message, null, errors),

  unauthorized: (
    res: Response,
    message = 'Unauthorized'
  ) => sendResponse(res, 401, message),

  forbidden: (
    res: Response,
    message = 'Forbidden'
  ) => sendResponse(res, 403, message),

  notFound: (
    res: Response,
    message = 'Resource not found'
  ) => sendResponse(res, 404, message),

  serverError: (
    res: Response,
    message = 'Internal server error',
    errors: any[] = []
  ) => sendResponse(res, 500, message, null, errors),

  handleError: (res: Response, error: unknown) => {
    if (error instanceof ApiError) {
      return sendResponse(
        res,
        error.statusCode,
        error.message,
        null,
        error.errors.length ? error.errors : undefined
      );
    }

    // For unexpected errors, safely extract info for development only
    const errorMessage =
      process.env.NODE_ENV === 'development'
        ? error instanceof Error
          ? error.message
          : String(error)
        : undefined;

    console.error('Unhandled error:', error);

    return sendResponse(res, 500, 'Internal server error', null, errorMessage);
  }
};

