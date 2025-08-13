import winston from 'winston';
import path from 'path';

const logFile = process.env.LOG_FILE_PATH || path.join(__dirname, '../../logs', 'app.log');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: logFile })
  ]
});

export default logger;