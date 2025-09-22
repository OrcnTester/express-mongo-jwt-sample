
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
