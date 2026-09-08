/** Rendimiento de red (NPM): estado en vivo de las interfaces del FortiGate. */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { getInterfacesLive } from './netperf.service';

export const netperfRouter = Router();
netperfRouter.use(authenticate);

netperfRouter.get('/interfaces', (_req: Request, res: Response) => {
  res.json(getInterfacesLive());
});
