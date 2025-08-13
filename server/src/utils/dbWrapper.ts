import dotenv from 'dotenv';
dotenv.config();

const env = process.env.NODE_ENV || 'development';
const models = require('../models'); // loads src/models/index.js (sequelize models)
const sequelize = models.sequelize;

export { sequelize, models };