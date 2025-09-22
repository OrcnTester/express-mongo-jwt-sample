
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
