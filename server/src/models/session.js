'use strict';
const { Model } = require('sequelize');

module.exports = (sequelize, DataTypes) => {
  class Session extends Model {
    static associate(models) {
      // A session belongs to a user (User model)
      if (models.User) {
        Session.belongsTo(models.User, { foreignKey: 'userId', as: 'user' });
      }
    }
  }

  Session.init(
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
      refreshToken: {
        type: DataTypes.TEXT,
        allowNull: false
      },
      userAgent: { // meta data about client system
        type: DataTypes.STRING,
        allowNull: true
      },
      ip: {
        type: DataTypes.STRING,
        allowNull: true
      },
      expiresAt: {
        type: DataTypes.DATE,
        allowNull: false
      },
      revoked: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
      }
    },
    {
      sequelize,
      modelName: 'Session',
      tableName: 'Sessions',
      timestamps: true,
      underscored: false
    }
  );

  return Session;
};