/**
 * Integración con Velociraptor (DFIR): permite lanzar colecciones/hunts en un
 * host desde HexWatch y listar los clientes. Llama a un helper Python que habla
 * con la API de Velociraptor (gRPC/mTLS) vía pyvelociraptor.
 */
import { Router, type Request, type Response } from 'express';
import { execFile } from 'node:child_process';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { auditFromReq } from '../audit/audit.service';

export const velociraptorRouter = Router();

const HELPER = process.env.VELO_HELPER || '/opt/soc-pnnc/velo/velo_helper.py';
const PY = process.env.VELO_PYTHON || 'python3';

/** Ejecuta el helper y devuelve el JSON parseado (o {error}). */
function runHelper(args: string[]): Promise<any> {
  return new Promise((resolve) => {
    execFile(PY, [HELPER, ...args], { timeout: 25_000, maxBuffer: 4_000_000 }, (err, stdout, stderr) => {
      const out = (stdout || '').trim();
      if (!out) { resolve({ error: (stderr || '').trim() || err?.message || 'sin respuesta' }); return; }
      try { resolve(JSON.parse(out)); }
      catch { resolve({ error: 'respuesta no válida de Velociraptor', raw: out.slice(0, 300) }); }
    });
  });
}

velociraptorRouter.use(authenticate);

// Estado de la integración (para que el UI muestre/oculte el botón).
velociraptorRouter.get('/status', requireRole('admin', 'analista'), async (_req, res) => {
  const r = await runHelper(['list']);
  if (Array.isArray(r)) res.json({ available: true, clients: r.length });
  else res.json({ available: false, error: r?.error ?? 'no disponible' });
});

// Clientes Velociraptor.
velociraptorRouter.get('/clients', requireRole('admin', 'analista'), async (_req, res) => {
  const r = await runHelper(['list']);
  if (Array.isArray(r)) res.json({ clients: r });
  else res.status(502).json(r);
});

// Colecciones (flows) recientes de un cliente.
velociraptorRouter.get('/clients/:clientId/flows', requireRole('admin', 'analista'), async (req: Request, res: Response) => {
  const clientId = String(req.params.clientId || '');
  if (!/^C\.[0-9a-f]{6,32}$/i.test(clientId)) {
    res.status(400).json({ error: 'client_id inválido' });
    return;
  }
  const r = await runHelper(['flows', clientId]);
  if (r?.error) { res.status(502).json(r); return; }
  res.json(r); // { client_id, flows: [...] }
});

// Lanzar colección forense en un host.
velociraptorRouter.post('/collect', requireRole('admin', 'analista'), async (req: Request, res: Response) => {
  const host = String(req.body?.host || '').trim();
  if (!host || !/^[A-Za-z0-9._-]{1,120}$/.test(host)) {
    res.status(400).json({ error: 'host inválido' });
    return;
  }
  const r = await runHelper(['collect', host]);
  if (r?.error) {
    res.status(502).json(r);
    return;
  }
  void auditFromReq(req, {
    actorId: req.user!.id, actorEmail: req.user!.email,
    action: 'velociraptor_collect', target: host, result: 'ok',
    detail: { flow_id: r.flow_id, client_id: r.client_id },
  });
  res.json(r);
});
