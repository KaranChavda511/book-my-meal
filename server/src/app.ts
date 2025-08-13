import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import routes from './routes';
import { errorMiddleware } from './middlewares/errorMiddleware';
import { sequelize } from './utils/dbWrapper'; // helper to init sequelize connection

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(helmet());


// CORS
const corsOrigins = (process.env.CORS_ORIGIN || '').split(',');
app.use(cors({ origin: corsOrigins.length ? corsOrigins : '*' }));

// Logger
app.use(morgan('dev'));

// Rate limiter
const limiter = rateLimit({
  windowMs: Number(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: Number(process.env.RATE_LIMIT_MAX_REQUESTS) || 100
});
app.use(limiter);

// Routes
app.use('/api', routes);

// Error handler (should be the last middleware)
app.use(errorMiddleware);

export default app;

