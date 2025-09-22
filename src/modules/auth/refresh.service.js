import crypto from 'crypto';
import RefreshToken from './refreshToken.model.js';
import { signJwt } from '../../lib/jwt.js';

const REFRESH_TTL_DAYS = parseInt(process.env.JWT_REFRESH_TTL_DAYS || '7', 10);

function generateRaw() {
  return crypto.randomBytes(48).toString('hex');
}
function hash(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

export async function issueRefresh(userId) {
  const raw = generateRaw();
  const tokenHash = hash(raw);
  const expiresAt = new Date(Date.now() + REFRESH_TTL_DAYS * 86400000);

  await RefreshToken.create({ userId, tokenHash, expiresAt });
  return { raw, expiresAt };
}

export async function rotateRefresh(oldRaw) {
  const oldHash = hash(oldRaw);
  const doc = await RefreshToken.findOne({ tokenHash: oldHash });
  if (!doc || doc.revoked) throw new Error('invalid_refresh');

  doc.revoked = true;
  const { raw: newRaw, expiresAt } = await issueRefresh(doc.userId);
  doc.replacedBy = hash(newRaw);
  await doc.save();

  const accessToken = signJwt({ id: doc.userId });
  return { accessToken, refreshToken: newRaw, refreshExpiresAt: expiresAt };
}

export async function revokeRefresh(raw) {
  await RefreshToken.updateOne({ tokenHash: hash(raw) }, { revoked: true });
}
