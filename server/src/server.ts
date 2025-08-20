import dotenv from 'dotenv';
dotenv.config();
const db = require("./models")


import app from './app';

const PORT = process.env.PORT || 3000;


const start = async () => {
  try {
    await db.sequelize.authenticate();
    console.log('✅ Database connected');
    app.listen(PORT, () => {
      console.log(`✅ Server running on port ${PORT}`);
    });
  } catch (err) {
    console.error('❌ Failed to start server', err);
    process.exit(1);
  }
};

start();