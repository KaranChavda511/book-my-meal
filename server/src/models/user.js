'use strict';
const { Model } = require('sequelize');

module.exports = (sequelize, DataTypes) => {
  class User extends Model {
    static associate(models) {
      // User has many sessions
      if (models.Session) {
        User.hasMany(models.Session, { foreignKey: 'userId', as: 'sessions' });
      }
    }
  }

  User.init(
    {
      firstName: {
        type: DataTypes.STRING,
        allowNull: false
      },
      lastName: {
        type: DataTypes.STRING
      },
      email: {
        type: DataTypes.STRING,
        unique: true,
        allowNull: false,
        validate: { isEmail: true }
      },
      password: {
        type: DataTypes.STRING,
        allowNull: false
      },
      phone: {
        type: DataTypes.STRING
      },
      role: {
        type: DataTypes.STRING,
        defaultValue: 'user'
      },
      isEmailVerified: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
      }
    },
    {
      sequelize,
      modelName: 'User',
      tableName: 'Users',
      underscored: false,
      timestamps: true
    }
  );

  return User;
};