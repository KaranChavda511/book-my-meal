export default class ApiError extends Error {
  statusCode: number;
  details?: any;

  constructor(statusCode = 500, message = 'Something went wrong', details?: any) {
    super(message);
    this.statusCode = statusCode;
    this.details = details;
    Error.captureStackTrace(this, this.constructor);
  }
}