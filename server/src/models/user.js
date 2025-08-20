"use strict";
const { Model } = require("sequelize");

module.exports = (sequelize, DataTypes) => {
  // here define associations
  class User extends Model {
    static associate(models) {
      if (models.Session) {
        User.hasMany(models.Session, { foreignKey: "userId", as: "sessions" });
      } // referes user has many sessions
    }
  }

  // User Table Schema
  User.init(
    {
      firstName: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      lastName: {
        type: DataTypes.STRING,
      },
      email: {
        type: DataTypes.STRING,
        unique: true,
        allowNull: false,
        validate: { isEmail: true },
      },
      password: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      phone: {
        type: DataTypes.STRING,
      },
      role: {
        type: DataTypes.ENUM("user", "admin", "rider", "restaurant_admin"), 
        allowNull: false,
        defaultValue: "user",
      },
      isEmailVerified: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
      },
    },
    {
      sequelize, // connections
      modelName: "User", // model name
      tableName: "Users", // database table name
      underscored: false, // field names won't use snake_case
      timestamps: true, // auto add CreatedAt, updatedAt
    }
  );

  return User;
};
