import { Request, Response, NextFunction } from "express";
import ApiError from "../utils/apiError";

// Higher-order middleware: checks if user role is one of the allowed
export const authorizeRoles = (...roles: string[]) => {
  return (req: Request, _res: Response, next: NextFunction) => {
    const user = (req as any).user;

    if (!user) {
      return next(new ApiError(401, "Unauthorized - user not found"));
    }

    if (!roles.includes(user.role)) {
      return next(new ApiError(403, "Forbidden - insufficient role"));
    }

    next();
  };
};
