'use strict';

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.addColumn('Users', 'avatarUrl', {
      type: Sequelize.STRING(512),
      allowNull: true
    });
  },

  async down(queryInterface) {
    await queryInterface.removeColumn('Users', 'avatarUrl');
  }

  
};
