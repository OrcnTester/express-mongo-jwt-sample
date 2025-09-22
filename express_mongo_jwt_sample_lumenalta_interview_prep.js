// =============================
// File: package.json
// =============================
{
  "name": "express-mongo-jwt-sample",
  "version": "1.0.0",
  "main": "src/server.js",
  "type": "module",
  "scripts": {
    "dev": "node --watch src/server.js",
    "start": "node src/server.js"
  },
  "dependencies": {
    "bcryptjs": "^2.4.3",
    "cors": "^2.8.5",
    "dotenv": "^16.4.5",
    "express": "^4.19.2",
    "jsonwebtoken": "^9.0.2",
    "mongoose": "^8.5.0",
    "morgan": "^1.10.0",
    "zod": "^3.23.8"
  }
}

// =============================
// File: .env.example
// =============================
# Copy this to .env and fill your values
PORT=3000
MONGO_URL=mongodb://localhost:27017/lumenalta_demo
JWT_SECRET=supersecret_change_me

// =============================
// File: src/server.js
// =============================
import './setup.js';
import app from './web.js';
import mongoose from 'mongoose';

const PORT = process.env.PORT || 3000;

async function main() {
  await mongoose.connect(process.env.MONGO_URL, {
    dbName: process.env.MONGO_DB || undefined,
  });
  console.log('✅ Mongo connected');
  app.listen(PORT, () => console.log(`🚀 API listening on http://localhost:${PORT}`));
}

main().catch((err) => {
  console.error('❌ Startup error:', err);
  process.exit(1);
});

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

// =============================
// File: src/lib/jwt.js
// =============================
import jwt from 'jsonwebtoken';

export function signJwt(payload, opts = {}) {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '2h', ...opts });
}

export function verifyJwt(token) {
  return jwt.verify(token, process.env.JWT_SECRET);
}

export function authMiddleware(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    const decoded = verifyJwt(token);
    req.user = decoded;
    return next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// =============================
// File: src/modules/users/user.model.js
// =============================
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const UserSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    name: { type: String, required: true, trim: true },
    passwordHash: { type: String, required: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
  },
  { timestamps: true }
);

UserSchema.methods.setPassword = async function setPassword(plain) {
  this.passwordHash = await bcrypt.hash(plain, 10);
};

UserSchema.methods.comparePassword = function comparePassword(plain) {
  return bcrypt.compare(plain, this.passwordHash);
};

export default mongoose.model('User', UserSchema);

// =============================
// File: src/modules/auth/auth.routes.js
// =============================
import { Router } from 'express';
import { z } from 'zod';
import User from '../users/user.model.js';
import { signJwt } from '../../lib/jwt.js';

const router = Router();

const registerSchema = z.object({
  email: z.string().email(),
  name: z.string().min(2),
  password: z.string().min(6),
});

router.post('/register', async (req, res, next) => {
  try {
    const body = registerSchema.parse(req.body);
    const exists = await User.findOne({ email: body.email });
    if (exists) return res.status(409).json({ error: 'Email already in use' });
    const user = new User({ email: body.email, name: body.name, passwordHash: 'x' });
    await user.setPassword(body.password);
    await user.save();
    const token = signJwt({ sub: user.id, email: user.email, role: user.role });
    res.status(201).json({ token, user: { id: user.id, email: user.email, name: user.name } });
  } catch (e) {
    next(e);
  }
});

const loginSchema = z.object({ email: z.string().email(), password: z.string().min(6) });

router.post('/login', async (req, res, next) => {
  try {
    const body = loginSchema.parse(req.body);
    const user = await User.findOne({ email: body.email });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await user.comparePassword(body.password);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = signJwt({ sub: user.id, email: user.email, role: user.role });
    res.json({ token, user: { id: user.id, email: user.email, name: user.name } });
  } catch (e) {
    next(e);
  }
});

export default router;

// =============================
// File: src/modules/users/user.routes.js
// =============================
import { Router } from 'express';
import { z } from 'zod';
import User from './user.model.js';
import { authMiddleware } from '../../lib/jwt.js';

const router = Router();

// Create user (admin-only example, but here we just require auth for demo)
const createSchema = z.object({
  email: z.string().email(),
  name: z.string().min(2),
  password: z.string().min(6),
  role: z.enum(['user', 'admin']).optional(),
});

router.post('/', authMiddleware, async (req, res, next) => {
  try {
    const body = createSchema.parse(req.body);
    const exists = await User.findOne({ email: body.email });
    if (exists) return res.status(409).json({ error: 'Email already in use' });
    const user = new User({ email: body.email, name: body.name, role: body.role || 'user', passwordHash: 'x' });
    await user.setPassword(body.password);
    await user.save();
    res.status(201).json({ id: user.id, email: user.email, name: user.name, role: user.role });
  } catch (e) {
    next(e);
  }
});

// Get one user by id
router.get('/:id', authMiddleware, async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id).select('-passwordHash');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (e) {
    next(e);
  }
});

// List users with pagination: /users?page=1&limit=10
router.get('/', authMiddleware, async (req, res, next) => {
  try {
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 10));
    const skip = (page - 1) * limit;

    const [items, total] = await Promise.all([
      User.find({}).select('-passwordHash').skip(skip).limit(limit).sort({ createdAt: -1 }),
      User.countDocuments({}),
    ]);

    res.json({
      page,
      limit,
      total,
      pages: Math.ceil(total / limit),
      items,
    });
  } catch (e) {
    next(e);
  }
});

export default router;

// =============================
// File: README.md
// =============================
# Express + Mongo + JWT — Mini Challenge Solution

A minimal, interview-ready API showcasing registration/login, protected routes, and pagination.

## Endpoints
- `GET /health` → quick health check.
- `POST /auth/register` → { email, name, password } → returns JWT + user.
- `POST /auth/login` → { email, password } → returns JWT + user.
- `POST /users` (auth) → create another user.
- `GET /users/:id` (auth)
- `GET /users?page=1&limit=10` (auth) → pagination.

## Run locally
```bash
cp .env.example .env
npm i
npm run dev
```
Open http://localhost:3000/health

## Quick test (HTTPie or curl)
```bash
# register
http POST :3000/auth/register email=demo@demo.io name=Demo password=secret12

# login
http POST :3000/auth/login email=demo@demo.io password=secret12
# copy the token from response

# create a user
http POST :3000/users \
  Authorization:"Bearer <TOKEN>" \
  email=second@demo.io name=Second password=secret12 role=user

# list users
http GET :3000/users Authorization:"Bearer <TOKEN>" page==1 limit==5

# get by id
http GET :3000/users/<ID> Authorization:"Bearer <TOKEN>"
```

## Notes
- Uses **Zod** for validation, **bcrypt** for password hashing, **JWT** for auth.
- Keeps handlers small & readable; centralized error handling.
- Easy to extend with roles/permissions and rate-limiting.
