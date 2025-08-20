"use strict";

module.exports = {
  up: async (queryInterface, Sequelize) => {
    // Alter column to ENUM (Sequelize will create the enum type automatically)
    await queryInterface.changeColumn("Users", "role", {
      type: Sequelize.ENUM("user", "admin", "rider", "restaurant_admin"),
      allowNull: false,
      defaultValue: "user",
    });
  },

  down: async (queryInterface, Sequelize) => {
    //  Revert back to STRING
    await queryInterface.changeColumn("Users", "role", {
      type: Sequelize.STRING,
      allowNull: false,
      defaultValue: "user",
    });

    // Manually  Drop ENUM type
    await queryInterface.sequelize.query(`
      DROP TYPE IF EXISTS "enum_Users_role";
    `);
  },
};
