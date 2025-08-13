import { createUser, findUserByEmail } from '../repositories/userRepository';
import { hashPassword, comparePassword } from '../helpers/passwordHelpers';
import { signAccessToken } from '../helpers/tokenhelper';
import ApiError from '../utils/apiError';

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

export const loginUser = async (payload: any) => {
  const user = await findUserByEmail(payload.email);
  if (!user) {
    throw new ApiError(401, 'Invalid credentials');
  }

  const isValid = await comparePassword(payload.password, user.password);
  if (!isValid) {
    throw new ApiError(401, 'Invalid credentials');
  }

  const token = signAccessToken({ id: user.id, email: user.email, role: user.role });

  return { user: { id: user.id, firstName: user.firstName, email: user.email }, token };
};