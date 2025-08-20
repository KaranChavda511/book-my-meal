'use strict';
const { Model } = require('sequelize');

module.exports = (sequelize, DataTypes) => {
  class PasswordReset extends Model {
    static associate(models) {
      if (models.User) {
        PasswordReset.belongsTo(models.User, { foreignKey: 'userId', as: 'user' });
      }
    }
  }

  PasswordReset.init(
    {
      id: {
        type: DataTypes.UUID,
        primaryKey: true,
        defaultValue: DataTypes.UUIDV4
      },
      userId: {
        type: DataTypes.UUID,
        allowNull: false
      },
      token: {
        type: DataTypes.STRING(255),
        allowNull: false,
        unique: true
      },
      expiresAt: {
        type: DataTypes.DATE,
        allowNull: false
      },
      used: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
      }
    },
    {
      sequelize,
      modelName: 'PasswordReset',
      tableName: 'PasswordResets',
      timestamps: true
    }
  );

  return PasswordReset;
};


