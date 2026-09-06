/**
 * Respaldos de la base de datos en formato propio .pnnc
 *
 * Estructura del archivo .pnnc (contenedor binario):
 *   [0..4)   magic  "PNNC"          (4 bytes ASCII)
 *   [4]      version 0x01           (1 byte)
 *   [5..9)   longitud metadata M    (uint32 big-endian)
 *   [9..9+M) metadata JSON (UTF-8)  { createdAt, dbName, appVersion, sha256, ... }
 *   [9+M..)  volcado SQL (pg_dump plano) comprimido con gzip
 *
 * El sha256 en la metadata corresponde al bloque gzip, para verificar
 * integridad al listar/restaurar. Solo rol admin.
 */
import { spawn } from 'node:child_process';
import { createGunzip, gzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { createReadStream } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { env } from '../../config/env';
import { logger } from '../../config/logger';

const MAGIC = Buffer.from('PNNC', 'ascii');
const VERSION = 1;
const APP_VERSION = '1.0.0';

export interface BackupMeta {
  createdAt: string;
  dbName: string;
  appVersion: string;
  generator: string;
  origin: 'manual' | 'automatico';
  note?: string;
  sha256: string;
  compressedBytes: number;
  uncompressedBytes: number;
}

export interface BackupItem {
  id: string; // nombre de archivo
  createdAt: string;
  origin: 'manual' | 'automatico';
  note: string | null;
  fileBytes: number;
  uncompressedBytes: number;
  integrity: 'ok' | 'corrupto' | 'desconocida';
}

export interface RecoveryPosture {
  estado: 'ok' | 'warn' | 'fail';
  totalBackups: number;
  lastBackupAt: string | null;
  lastBackupAgeHours: number | null;
  fresh: boolean;
  totalBytes: number;
  retention: number;
  cron: string;
  integrity: { ok: number; corrupto: number; desconocida: number };
  offsite: boolean;
  location: string;
  scope: string;
  warnings: string[];
}

/** Postura de recuperación: la VERDAD sobre qué tan protegido está el SOC (no solo la lista). */
export async function getRecoveryPosture(): Promise<RecoveryPosture> {
  const backups = await listBackups(); // ordenados por fecha desc
  const last = backups[0] ?? null;
  const ageHours = last ? (Date.now() - Date.parse(last.createdAt)) / 3_600_000 : null;
  const fresh = ageHours != null && ageHours < 30; // cron diario → un respaldo sano tiene <30h
  const integrity = { ok: 0, corrupto: 0, desconocida: 0 };
  for (const b of backups) integrity[b.integrity] += 1;
  const totalBytes = backups.reduce((s, b) => s + b.fileBytes, 0);
  const offsite = false; // no hay mecanismo de copia externa: todo vive en este servidor

  const warnings: string[] = [];
  let estado: RecoveryPosture['estado'] = 'ok';
  if (backups.length === 0) {
    warnings.push('No hay ningún respaldo. No tienes punto de recuperación.');
    estado = 'fail';
  } else {
    if (!fresh) {
      warnings.push(`El último respaldo es de hace ~${Math.round((ageHours ?? 0) / 24)} día(s). Revisa el respaldo automático (cron ${env.BACKUP_CRON}) — puede estar fallando en silencio.`);
      estado = 'warn';
    }
    if (integrity.corrupto > 0) {
      warnings.push(`${integrity.corrupto} respaldo(s) con integridad CORRUPTA: no servirían para restaurar.`);
      estado = 'fail';
    }
  }
  if (!offsite) {
    warnings.push('Sin copia externa: todos los respaldos están en el mismo servidor que la base de datos. Si el servidor se pierde (falla de disco, ransomware, borrado), se pierden con él. Recomendado: copiar los .pnnc a un destino externo (otro servidor, NAS o nube).');
    if (estado === 'ok') estado = 'warn';
  }

  return {
    estado,
    totalBackups: backups.length,
    lastBackupAt: last?.createdAt ?? null,
    lastBackupAgeHours: ageHours != null ? Math.round(ageHours * 10) / 10 : null,
    fresh,
    totalBytes,
    retention: env.BACKUP_RETENTION,
    cron: env.BACKUP_CRON,
    integrity,
    offsite,
    location: backupDir(),
    scope: 'Base de datos de la plataforma (incidentes, reglas, usuarios, configuración, bitácora). NO incluye el archivo .env (secretos/tokens) ni las reglas de Wazuh del manager (local_rules.xml).',
    warnings,
  };
}

function backupDir(): string {
  return env.BACKUP_DIR ?? path.join(os.homedir(), 'soc-pnnc-backups');
}

/** Parte la DATABASE_URL para no pasar la contrasena por argv (va en PGPASSWORD). */
function pgConn(): { args: string[]; env: NodeJS.ProcessEnv; dbName: string } {
  const u = new URL(env.DATABASE_URL);
  const dbName = u.pathname.replace(/^\//, '') || 'postgres';
  const args = ['-h', u.hostname, '-p', u.port || '5432', '-U', decodeURIComponent(u.username), '-d', dbName];
  return { args, env: { ...process.env, PGPASSWORD: decodeURIComponent(u.password) }, dbName };
}

/** Valida que el id sea un nombre de archivo .pnnc simple (anti path traversal). */
function safeName(id: string): string {
  if (!/^[A-Za-z0-9._-]+\.pnnc$/.test(id) || id.includes('..')) {
    throw new HttpBackupError(400, 'Nombre de respaldo invalido');
  }
  return id;
}

export class HttpBackupError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

/** Ejecuta pg_dump (SQL plano) y devuelve el volcado como Buffer. */
function pgDump(): Promise<Buffer> {
  const { args, env: pgEnv } = pgConn();
  return new Promise((resolve, reject) => {
    const proc = spawn('pg_dump', ['--no-owner', '--no-privileges', ...args], { env: pgEnv });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    proc.stdout.on('data', (c: Buffer) => out.push(c));
    proc.stderr.on('data', (c: Buffer) => err.push(c));
    proc.on('error', reject);
    proc.on('close', (code) => {
      if (code === 0) resolve(Buffer.concat(out));
      else reject(new Error(`pg_dump salio con codigo ${code}: ${Buffer.concat(err).toString().slice(0, 300)}`));
    });
  });
}

/** Crea un respaldo .pnnc y lo guarda en disco. */
export async function createBackup(opts: { origin?: 'manual' | 'automatico'; note?: string } = {}): Promise<BackupItem> {
  const dir = backupDir();
  await fs.mkdir(dir, { recursive: true });

  const sql = await pgDump();
  const gz = gzipSync(sql, { level: 9 });
  const sha256 = createHash('sha256').update(gz).digest('hex');
  const { dbName } = pgConn();
  const createdAt = new Date().toISOString();
  const meta: BackupMeta = {
    createdAt,
    dbName,
    appVersion: APP_VERSION,
    generator: 'soc-pnnc-backend',
    origin: opts.origin ?? 'manual',
    note: opts.note,
    sha256,
    compressedBytes: gz.length,
    uncompressedBytes: sql.length,
  };
  const metaBuf = Buffer.from(JSON.stringify(meta), 'utf-8');
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(metaBuf.length, 0);
  const header = Buffer.concat([MAGIC, Buffer.from([VERSION]), lenBuf, metaBuf]);
  const file = Buffer.concat([header, gz]);

  const stamp = createdAt.replace(/[-:]/g, '').replace(/\..+/, '').replace('T', '-');
  const id = `soc-pnnc-${stamp}.pnnc`;
  await fs.writeFile(path.join(dir, id), file, { mode: 0o600 });
  logger.info({ id, bytes: file.length, origin: meta.origin }, 'Respaldo .pnnc creado');

  return {
    id,
    createdAt,
    origin: meta.origin,
    note: meta.note ?? null,
    fileBytes: file.length,
    uncompressedBytes: meta.uncompressedBytes,
    integrity: 'ok',
  };
}

/** Lee el header .pnnc (magic + metadata) sin cargar el dump completo. */
async function readMeta(fullPath: string): Promise<{ meta: BackupMeta; fileBytes: number } | null> {
  const fd = await fs.open(fullPath, 'r');
  try {
    const head = Buffer.alloc(9);
    await fd.read(head, 0, 9, 0);
    if (!head.subarray(0, 4).equals(MAGIC)) return null;
    const mLen = head.readUInt32BE(5);
    const mBuf = Buffer.alloc(mLen);
    await fd.read(mBuf, 0, mLen, 9);
    const meta = JSON.parse(mBuf.toString('utf-8')) as BackupMeta;
    const { size } = await fd.stat();
    return { meta, fileBytes: size };
  } catch {
    return null;
  } finally {
    await fd.close();
  }
}

export async function listBackups(): Promise<BackupItem[]> {
  const dir = backupDir();
  let names: string[];
  try {
    names = (await fs.readdir(dir)).filter((n) => n.endsWith('.pnnc'));
  } catch {
    return [];
  }
  const items: BackupItem[] = [];
  for (const id of names) {
    const info = await readMeta(path.join(dir, id));
    if (!info) {
      items.push({ id, createdAt: '', origin: 'manual', note: null, fileBytes: 0, uncompressedBytes: 0, integrity: 'corrupto' });
      continue;
    }
    items.push({
      id,
      createdAt: info.meta.createdAt,
      origin: info.meta.origin,
      note: info.meta.note ?? null,
      fileBytes: info.fileBytes,
      uncompressedBytes: info.meta.uncompressedBytes,
      integrity: 'desconocida',
    });
  }
  items.sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
  return items;
}

export function backupFilePath(id: string): string {
  return path.join(backupDir(), safeName(id));
}

export async function backupExists(id: string): Promise<boolean> {
  try {
    await fs.access(backupFilePath(id));
    return true;
  } catch {
    return false;
  }
}

export async function deleteBackup(id: string): Promise<boolean> {
  const p = backupFilePath(id);
  try {
    await fs.unlink(p);
    logger.info({ id }, 'Respaldo .pnnc eliminado');
    return true;
  } catch {
    return false;
  }
}

/** Conserva los N respaldos automaticos mas recientes; borra el resto. */
export async function enforceRetention(keep: number): Promise<number> {
  const autos = (await listBackups()).filter((b) => b.origin === 'automatico');
  const sobran = autos.slice(keep);
  for (const b of sobran) await deleteBackup(b.id);
  if (sobran.length) logger.info({ borrados: sobran.length, keep }, 'Retencion de respaldos aplicada');
  return sobran.length;
}

/** Verifica la integridad (sha256 del bloque gzip) de un respaldo. */
export async function verifyBackup(id: string): Promise<'ok' | 'corrupto'> {
  const p = backupFilePath(id);
  const info = await readMeta(p);
  if (!info) return 'corrupto';
  const gzStart = 9 + Buffer.byteLength(JSON.stringify(info.meta), 'utf-8');
  return new Promise((resolve) => {
    const hash = createHash('sha256');
    const stream = createReadStream(p, { start: gzStart });
    stream.on('data', (c) => hash.update(c));
    stream.on('end', () => resolve(hash.digest('hex') === info.meta.sha256 ? 'ok' : 'corrupto'));
    stream.on('error', () => resolve('corrupto'));
  });
}

export { createGunzip };
