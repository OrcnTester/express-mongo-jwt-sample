
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
