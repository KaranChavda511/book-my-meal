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