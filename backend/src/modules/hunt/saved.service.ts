/**
 * Cacerías guardadas: consultas de threat hunting almacenadas, con alerta
 * opcional cuando el numero de coincidencias supera un umbral. El scheduler
 * corre las cacerías con alerta activa en su intervalo y notifica (in-app).
 */
import { query } from '../../config/db';
import { logger } from '../../config/logger';
import { hunt, type HuntParams } from './hunt.service';
import { logNotification } from '../notifications/notify.engine';

export interface SavedHunt {
  id: string;
  name: string;
  query: HuntParams;
  alertEnabled: boolean;
  threshold: number;
  intervalMin: number;
  lastRun: string | null;
  lastCount: number | null;
  createdBy: string | null;
  createdAt: string;
}

interface Row {
  id: string; name: string; query: HuntParams; alert_enabled: boolean; threshold: number;
  interval_min: number; last_run: string | null; last_count: number | null;
  created_by: string | null; created_at: string;
}

const toHunt = (r: Row): SavedHunt => ({
  id: r.id, name: r.name, query: r.query, alertEnabled: r.alert_enabled, threshold: r.threshold,
  intervalMin: r.interval_min, lastRun: r.last_run, lastCount: r.last_count,
  createdBy: r.created_by, createdAt: r.created_at,
});

export async function listSavedHunts(): Promise<SavedHunt[]> {
  const rows = await query<Row>('SELECT * FROM saved_hunts ORDER BY created_at DESC');
  return rows.map(toHunt);
}

export async function createSavedHunt(data: {
  name: string; query: HuntParams; alertEnabled?: boolean; threshold?: number; intervalMin?: number; createdBy: string;
}): Promise<SavedHunt> {
  const rows = await query<Row>(
    `INSERT INTO saved_hunts (name, query, alert_enabled, threshold, interval_min, created_by)
     VALUES ($1,$2::jsonb,$3,$4,$5,$6) RETURNING *`,
    [data.name, JSON.stringify(data.query), data.alertEnabled ?? false, data.threshold ?? 1, data.intervalMin ?? 15, data.createdBy]
  );
  return toHunt(rows[0]);
}

export async function updateSavedHunt(id: string, data: Partial<{
  name: string; query: HuntParams; alertEnabled: boolean; threshold: number; intervalMin: number;
}>): Promise<SavedHunt | null> {
  const rows = await query<Row>(
    `UPDATE saved_hunts SET
       name = COALESCE($2, name),
       query = COALESCE($3::jsonb, query),
       alert_enabled = COALESCE($4, alert_enabled),
       threshold = COALESCE($5, threshold),
       interval_min = COALESCE($6, interval_min)
     WHERE id = $1 RETURNING *`,
    [id, data.name ?? null, data.query ? JSON.stringify(data.query) : null,
     data.alertEnabled ?? null, data.threshold ?? null, data.intervalMin ?? null]
  );
  return rows[0] ? toHunt(rows[0]) : null;
}

export async function deleteSavedHunt(id: string): Promise<boolean> {
  const rows = await query<{ id: string }>('DELETE FROM saved_hunts WHERE id = $1 RETURNING id', [id]);
  return rows.length > 0;
}

/** Corre una cacería y actualiza last_run/last_count. */
export async function runSavedHunt(id: string): Promise<{ total: number } | null> {
  const rows = await query<Row>('SELECT * FROM saved_hunts WHERE id = $1', [id]);
  if (!rows[0]) return null;
  const h = toHunt(rows[0]);
  const res = await hunt(h.query);
  await query('UPDATE saved_hunts SET last_run = now(), last_count = $2 WHERE id = $1', [id, res.total]);
  return { total: res.total };
}

// -------------------- Scheduler de alerta --------------------

async function due(): Promise<SavedHunt[]> {
  const rows = await query<Row>(
    `SELECT * FROM saved_hunts
      WHERE alert_enabled = TRUE
        AND (last_run IS NULL OR last_run < now() - (interval_min || ' minutes')::interval)`
  );
  return rows.map(toHunt);
}

// -------------------- Biblioteca de hipótesis de caza (semilla) --------------------
// Cacerías curadas para un entorno Windows + M365 + FortiGate, mapeadas a ATT&CK.
// Se siembran una sola vez (idempotente por nombre); arrancan con alerta apagada
// para no generar ruido — el analista activa las que quiera como detección permanente.
// Las que usan `mitre`/`q` de una técnica concreta corren en crudo (sin lente señal).
const HUNT_LIBRARY: { name: string; query: HuntParams }[] = [
  { name: 'Malware / antivirus detectó amenaza', query: { range: '7d', q: 'malware' } },
  { name: 'Manipulación de cuentas privilegiadas', query: { range: '7d', mitre: 'T1098' } },
  { name: 'Fuerza bruta / password spray', query: { range: '7d', mitre: 'T1110' } },
  { name: 'Acceso remoto entrante (RDP)', query: { range: '7d', mitre: 'T1021.001' } },
  { name: 'Cambio de política de dominio (GPO)', query: { range: '7d', mitre: 'T1484' } },
  { name: 'Ejecución de comandos / PowerShell', query: { range: '7d', mitre: 'T1059.001' } },
  { name: 'Borrado de logs de eventos', query: { range: '30d', q: 'cleared' } },
  { name: 'Reenvío de correo / regla de buzón (O365)', query: { range: '30d', q: 'forward' } },
  { name: 'Enlaces anónimos / compartir a externos (O365)', query: { range: '7d', q: 'anonymous' } },
  { name: 'Antivirus/Defender deshabilitado', query: { range: '7d', q: 'disabled', minLevel: 5 } },
];

export async function seedHuntLibrary(): Promise<void> {
  try {
    const existing = await query<{ name: string }>('SELECT name FROM saved_hunts');
    const have = new Set(existing.map((r) => r.name));
    let added = 0;
    for (const h of HUNT_LIBRARY) {
      if (have.has(h.name)) continue;
      const rows = await query<Row>(
        `INSERT INTO saved_hunts (name, query, alert_enabled, threshold, interval_min, created_by)
         VALUES ($1,$2::jsonb,FALSE,1,60,NULL) RETURNING *`,
        [h.name, JSON.stringify(h.query)]
      );
      // Corre una vez para poblar last_count (valor inmediato en la UI).
      try {
        const res = await hunt(h.query);
        await query('UPDATE saved_hunts SET last_run = now(), last_count = $2 WHERE id = $1', [rows[0].id, res.total]);
      } catch { /* índice aún no disponible; el scheduler lo poblará luego */ }
      added++;
    }
    if (added) logger.info({ added }, 'Biblioteca de cacerías sembrada');
  } catch (err) {
    logger.error({ err }, 'No se pudo sembrar la biblioteca de cacerías');
  }
}

export function startSavedHuntScheduler(): void {
  void seedHuntLibrary();
  const tick = async (): Promise<void> => {
    let hunts: SavedHunt[];
    try {
      hunts = await due();
    } catch {
      return;
    }
    for (const h of hunts) {
      try {
        const res = await hunt(h.query);
        await query('UPDATE saved_hunts SET last_run = now(), last_count = $2 WHERE id = $1', [h.id, res.total]);
        if (res.total >= h.threshold) {
          await logNotification({
            tipo: 'immediate',
            ruleName: `Cacería "${h.name}": ${res.total} coincidencia(s) (umbral ${h.threshold})`,
            origen: 'threat-hunting', recipients: [], status: 'sent',
          });
          logger.info({ hunt: h.name, total: res.total, threshold: h.threshold }, 'Cacería guardada disparo alerta');
        }
      } catch (err) {
        logger.error({ err, hunt: h.name }, 'Fallo corriendo cacería guardada');
      }
    }
  };
  void tick();
  setInterval(() => void tick(), 60_000); // revisa cada minuto que hay pendiente
  logger.info('Scheduler de cacerías guardadas activo');
}
