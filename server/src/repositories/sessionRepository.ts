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