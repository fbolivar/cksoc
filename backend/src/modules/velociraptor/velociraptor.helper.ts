/**
 * Ejecuta el helper Python que habla con la API de Velociraptor (gRPC/mTLS) y
 * devuelve su JSON. Compartido por las rutas y el motor SOAR.
 */
import { execFile } from 'node:child_process';

const HELPER = process.env.VELO_HELPER || '/opt/soc-pnnc/velo/velo_helper.py';
const PY = process.env.VELO_PYTHON || 'python3';

export function runHelper(args: string[]): Promise<any> {
  return new Promise((resolve) => {
    execFile(PY, [HELPER, ...args], { timeout: 25_000, maxBuffer: 4_000_000 }, (err, stdout, stderr) => {
      const out = (stdout || '').trim();
      if (!out) { resolve({ error: (stderr || '').trim() || err?.message || 'sin respuesta' }); return; }
      try { resolve(JSON.parse(out)); }
      catch { resolve({ error: 'respuesta no válida de Velociraptor', raw: out.slice(0, 300) }); }
    });
  });
}
