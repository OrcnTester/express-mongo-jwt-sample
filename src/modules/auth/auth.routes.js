// =============================
// File: src/modules/auth/auth.routes.js
// =============================
import { Router } from 'express';
import { z } from 'zod';
import User from '../users/user.model.js';
import { signJwt } from '../../lib/jwt.js';
import { issueRefresh, rotateRefresh, revokeRefresh } from './refresh.service.js';

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

    const accessToken = signJwt({ sub: user.id, email: user.email, role: user.role });
    const { raw: refreshToken, expiresAt: refreshExpiresAt } = await issueRefresh(user.id);

    res.json({
      accessToken,
      refreshToken,       
      refreshExpiresAt,
      user: { id: user.id, email: user.email, name: user.name },
    });
  } catch (e) {
    next(e);
  }
});

const refreshSchema = z.object({ refreshToken: z.string().min(20) });

router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = refreshSchema.parse(req.body);
    const { accessToken, refreshToken: newRefresh, refreshExpiresAt } = await rotateRefresh(refreshToken);
    res.json({ accessToken, refreshToken: newRefresh, refreshExpiresAt });
  } catch {
    res.status(401).json({ error: 'Invalid refresh token' });
  }
});

const logoutSchema = z.object({ refreshToken: z.string().min(20) });

router.post('/logout', async (req, res, next) => {
  try {
    const { refreshToken } = logoutSchema.parse(req.body);
    await revokeRefresh(refreshToken);
    res.json({ message: 'Logged out' });
  } catch (e) {
    next(e);
  }
});

export default router;
