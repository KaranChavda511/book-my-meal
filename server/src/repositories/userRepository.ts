const models = require('../models');
const { User } = models;

// create user in db
export const createUser = async (data: any) => {
  return User.create(data);
};

// find user by email in db
export const findUserByEmail = async (email: string) => {
  return User.findOne({ where: { email } });
};

// find user by id in db
export const findUserById = async (id: string) => {
  return User.findByPk(id);
};

// update user
export const updateUser = async (id: string, updates: any) => {
  const user = await findUserById(id);
  if (!user) return null;
  await user.update(updates);
  // remove password from returned object
  const JSONUser = user.toJSON();
  delete JSONUser.password;
  return JSONUser;
};

// delete user 
export const deleteUser = async (id: string) => {
  const user = await findUserById(id);
  if (!user) return null;
  return user.destroy();
};

// update user password
export const updateUserPassword = async (id: string, passwordHash: string) => {
  const user = await findUserById(id);
  if (!user) return null;
  await user.update({ password: passwordHash });
  const JSONUser = user.toJSON();
  delete JSONUser.password;
  return JSONUser;
};


