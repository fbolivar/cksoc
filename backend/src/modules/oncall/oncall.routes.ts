/**
 * On-call (turnos de guardia).
 *   GET    /api/oncall?from=&to=   -> turnos en la ventana
 *   GET    /api/oncall/current      -> quién está de guardia ahora
 *   POST   /api/oncall  (admin)     -> crear turno
 *   DELETE /api/oncall/:id (admin)  -> borrar turno
 *   POST   /api/oncall/test (admin) -> enviar un escalamiento de prueba al de guardia
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { listShifts, currentOnCall, createShift, deleteShift, notifyOnCall } from './oncall.service';

export const oncallRouter = Router();
oncallRouter.use(authenticate);
const onlyAdmin = requireRole('admin');

oncallRouter.get('/', async (req: Request, res: Response) => {
  try {
    const now = new Date();
    const from = typeof req.query.from === 'string' ? req.query.from : new Date(now.getTime() - 7 * 864e5).toISOString();
    const to = typeof req.query.to === 'string' ? req.query.to : new Date(now.getTime() + 30 * 864e5).toISOString();
    res.json({ shifts: await listShifts(from, to) });
  } catch {
    res.status(500).json({ error: 'No se pudieron cargar los turnos' });
  }
});

oncallRouter.get('/current', async (_req: Request, res: Response) => {
  try {
    res.json({ current: await currentOnCall() });
  } catch {
    res.status(500).json({ error: 'No se pudo determinar la guardia actual' });
  }
});

oncallRouter.post('/', onlyAdmin, async (req: Request, res: Response) => {
  const { userId, startsAt, endsAt, note } = req.body ?? {};
  if (!userId || !startsAt || !endsAt) { res.status(400).json({ error: 'userId, startsAt y endsAt son obligatorios' }); return; }
  if (new Date(endsAt) <= new Date(startsAt)) { res.status(400).json({ error: 'El fin debe ser posterior al inicio' }); return; }
  try {
    res.status(201).json(await createShift({ userId, startsAt, endsAt, note }, req.user!.id));
  } catch {
    res.status(500).json({ error: 'No se pudo crear el turno' });
  }
});

oncallRouter.delete('/:id', onlyAdmin, async (req: Request, res: Response) => {
  try {
    await deleteShift(req.params.id);
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: 'No se pudo borrar el turno' });
  }
});

oncallRouter.post('/test', onlyAdmin, async (_req: Request, res: Response) => {
  try {
    const r = await notifyOnCall('Prueba de escalamiento on-call', 'Este es un mensaje de prueba del escalamiento de guardia de HexWatch. Si lo recibes, el canal funciona.');
    res.json(r);
  } catch {
    res.status(500).json({ error: 'No se pudo enviar la prueba' });
  }
});
