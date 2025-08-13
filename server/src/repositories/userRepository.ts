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