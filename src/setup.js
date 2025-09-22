
// =============================
// File: src/setup.js
// =============================
import dotenv from 'dotenv';
dotenv.config();

// =============================
// File: src/web.js
// =============================
import express from 'express';
import morgan from 'morgan';
import cors from 'cors';
import authRoutes from './modules/auth/auth.routes.js';
import userRoutes from './modules/users/user.routes.js';

const app = express();
app.use(cors());
app.use(express.json());
app.use(morgan('dev'));

app.get('/health', (req, res) => res.json({ ok: true, ts: new Date().toISOString() }));

app.use('/auth', authRoutes);
app.use('/users', userRoutes);

// 404
app.use((req, res) => res.status(404).json({ error: 'Not Found' }));

// Error handler
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  const status = err.status || 500;
  res.status(status).json({ error: err.message || 'Internal Server Error' });
});

export default app;
