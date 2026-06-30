/**
 * Autenticacion en dos pasos (2FA) basada en TOTP (RFC 6238).
 * - El secreto se guarda CIFRADO en BD (AES-256-GCM, clave derivada del JWT_SECRET).
 * - Compatible con Google/Microsoft Authenticator, Authy, etc.
 * - Codigos de respaldo de un solo uso (hash SHA-256) para recuperacion.
 */
import { authenticator } from 'otplib';
import QRCode from 'qrcode';
import bcrypt from 'bcryptjs';
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'crypto';
import { query } from '../../config/db';
import { env } from '../../config/env';
import { HttpError } from './auth.service';

// Tolera +/- 1 ventana (30s) de desfase de reloj entre el telefono y el servidor.
authenticator.options = { window: 1 };

const ISSUER = 'SOC PNNC';
const KEY = createHash('sha256').update(`${env.JWT_SECRET}|totp-v1`).digest(); // 32 bytes

function encrypt(plain: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', KEY, iv);
  const ct = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [iv.toString('base64'), tag.toString('base64'), ct.toString('base64')].join(':');
}

function decrypt(blob: string): string {
  const [ivb, tagb, ctb] = blob.split(':');
  const decipher = createDecipheriv('aes-256-gcm', KEY, Buffer.from(ivb, 'base64'));
  decipher.setAuthTag(Buffer.from(tagb, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(ctb, 'base64')), decipher.final()]).toString('utf8');
}

const hashCode = (c: string) => createHash('sha256').update(c).digest('hex');
const normalize = (c: string) => c.replace(/[\s-]/g, '').toLowerCase();

interface Row {
  totp_secret: string | null;
  totp_enabled: boolean;
  totp_backup_codes: string[] | null;
  password_hash: string;
}

async function load(userId: string): Promise<Row> {
  const rows = await query<Row>(
    'SELECT totp_secret, totp_enabled, totp_backup_codes, password_hash FROM users WHERE id = $1',
    [userId]
  );
  if (!rows[0]) throw new HttpError(404, 'Usuario no encontrado');
  return rows[0];
}

export async function getStatus(userId: string): Promise<{ enabled: boolean }> {
  const r = await load(userId);
  return { enabled: r.totp_enabled };
}

/** Genera un secreto nuevo (aun sin activar) y devuelve el QR para enrolar. */
export async function setup(userId: string, email: string): Promise<{ otpauth: string; qr: string; secret: string }> {
  const secret = authenticator.generateSecret();
  const otpauth = authenticator.keyuri(email, ISSUER, secret);
  const qr = await QRCode.toDataURL(otpauth, { margin: 1, width: 220 });
  // Guarda el secreto cifrado pero deja 2FA desactivado hasta confirmar un codigo.
  await query('UPDATE users SET totp_secret = $1, totp_enabled = FALSE WHERE id = $2', [encrypt(secret), userId]);
  return { otpauth, qr, secret };
}

/** Confirma el codigo del enrolamiento, activa 2FA y entrega los codigos de respaldo (una sola vez). */
export async function enable(userId: string, code: string): Promise<{ backupCodes: string[] }> {
  const r = await load(userId);
  if (!r.totp_secret) throw new HttpError(400, 'Primero genere el código QR (setup)');
  if (r.totp_enabled) throw new HttpError(400, 'El 2FA ya está activado');
  const secret = decrypt(r.totp_secret);
  if (!authenticator.verify({ token: normalize(code), secret })) {
    throw new HttpError(401, 'Código inválido. Verifique la hora del dispositivo e intente de nuevo.');
  }
  // 10 codigos de respaldo de un solo uso (formato XXXX-XXXX).
  const plain = Array.from({ length: 10 }, () => {
    const h = randomBytes(4).toString('hex'); // 8 chars
    return `${h.slice(0, 4)}-${h.slice(4)}`;
  });
  const hashes = plain.map((c) => hashCode(normalize(c)));
  await query('UPDATE users SET totp_enabled = TRUE, totp_backup_codes = $1 WHERE id = $2', [hashes, userId]);
  return { backupCodes: plain };
}

/** Desactiva 2FA. Exige contrasena + un codigo TOTP/respaldo valido. */
export async function disable(userId: string, password: string, code: string): Promise<void> {
  const r = await load(userId);
  if (!r.totp_enabled) throw new HttpError(400, 'El 2FA no está activado');
  if (!(await bcrypt.compare(password, r.password_hash))) {
    throw new HttpError(401, 'Contraseña incorrecta');
  }
  if (!(await verifyCode(userId, code))) {
    throw new HttpError(401, 'Código 2FA inválido');
  }
  await query('UPDATE users SET totp_secret = NULL, totp_enabled = FALSE, totp_backup_codes = NULL WHERE id = $1', [userId]);
}

/**
 * Verifica un codigo durante el login (o al desactivar): primero como TOTP y,
 * si falla, como codigo de respaldo (que se consume al usarse).
 */
export async function verifyCode(userId: string, code: string): Promise<boolean> {
  const r = await load(userId);
  if (!r.totp_secret || !r.totp_enabled) return false;
  const input = normalize(code);
  const secret = decrypt(r.totp_secret);
  if (authenticator.verify({ token: input, secret })) return true;

  const codes = r.totp_backup_codes ?? [];
  const h = hashCode(input);
  if (codes.includes(h)) {
    await query('UPDATE users SET totp_backup_codes = $1 WHERE id = $2', [codes.filter((x) => x !== h), userId]);
    return true;
  }
  return false;
}
