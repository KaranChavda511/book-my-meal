const models = require('../models');
const { User } = models;

export const createUser = async (data: any) => {
  return User.create(data);
};

export const findUserByEmail = async (email: string) => {
  return User.findOne({ where: { email } });
};

export const findUserById = async (id: string) => {
  return User.findByPk(id);
};