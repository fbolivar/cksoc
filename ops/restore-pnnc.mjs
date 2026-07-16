#!/usr/bin/env node
/**
 * Restauracion de un respaldo .pnnc hacia una base de datos PostgreSQL.
 *
 *   node ops/restore-pnnc.mjs <archivo.pnnc> <postgresql://...> [--yes]
 *
 * - Valida el contenedor (magic PNNC + version) y el checksum SHA-256 del
 *   volcado antes de tocar nada.
 * - Restaura contra la URL destino que se pase (NO usa la de la app por
 *   defecto: hay que darla explicita para evitar sobreescribir produccion
 *   por accidente).
 * - Pide --yes para ejecutar; sin el, solo muestra los metadatos (dry-run).
 *
 * Formato .pnnc:
 *   [0..4) "PNNC" | [4] version | [5..9) uint32BE len(meta) | meta JSON | gzip(SQL)
 */
import { readFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';

const [file, target, ...flags] = process.argv.slice(2);
const yes = flags.includes('--yes');

if (!file || !target) {
  console.error('Uso: node ops/restore-pnnc.mjs <archivo.pnnc> <postgresql://user:pass@host/db> [--yes]');
  process.exit(2);
}

const buf = readFileSync(file);
if (buf.subarray(0, 4).toString('ascii') !== 'PNNC') {
  console.error('No es un archivo .pnnc valido (magic incorrecto).');
  process.exit(1);
}
const version = buf[4];
const metaLen = buf.readUInt32BE(5);
const meta = JSON.parse(buf.subarray(9, 9 + metaLen).toString('utf-8'));
const gz = buf.subarray(9 + metaLen);
const sha = createHash('sha256').update(gz).digest('hex');
const integrityOk = sha === meta.sha256;

console.log('Respaldo .pnnc');
console.log('  version        :', version);
console.log('  creado         :', meta.createdAt);
console.log('  base de datos  :', meta.dbName);
console.log('  origen         :', meta.origin, meta.note ? `(${meta.note})` : '');
console.log('  integridad     :', integrityOk ? 'OK (sha256 coincide)' : 'CORRUPTO (sha256 NO coincide)');
console.log('  destino        :', target.replace(/:[^:@/]+@/, ':***@'));

if (!integrityOk) {
  console.error('\nAbortado: el respaldo esta corrupto.');
  process.exit(1);
}
if (!yes) {
  console.log('\n(dry-run) Agrega --yes para restaurar de verdad. ESTO SOBREESCRIBE la BD destino.');
  process.exit(0);
}

const sql = gunzipSync(gz);
console.log(`\nRestaurando ${sql.length} bytes de SQL...`);
const r = spawnSync('psql', [target, '-v', 'ON_ERROR_STOP=1'], { input: sql, stdio: ['pipe', 'inherit', 'inherit'] });
if (r.status !== 0) {
  console.error('\npsql fallo (codigo ' + r.status + ').');
  process.exit(1);
}
console.log('Restauracion completada.');
