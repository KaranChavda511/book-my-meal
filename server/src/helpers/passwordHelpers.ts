import bcrypt from 'bcryptjs';

const SALT_ROUNDS = Number(process.env.BCRYPT_SALT_ROUNDS) || 12;

export const hashPassword = async (password: string): Promise<string> => {
  const salt = await bcrypt.genSalt(SALT_ROUNDS);
  return bcrypt.hash(password, salt);
};

export const comparePassword = async (password: string, hash: string): Promise<boolean> => {
  return bcrypt.compare(password, hash);
};