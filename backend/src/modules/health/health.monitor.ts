/**
 * Monitor de Salud del SIEM. Cada HEALTH_POLL_SECONDS recalcula el estado,
 * registra los CAMBIOS en health_log y notifica las transiciones
 * (bueno->malo = alerta; malo->bueno = recuperacion). Anti-flood: como solo
 * actua en transiciones, no repite la alerta mientras el fallo persista.
 */
import { query } from '../../config/db';
import { env } from '../../config/env';
import { refreshHealth, type Estado } from './siem-health.service';
import { notifyHealthChange } from './health.notifier';

const lastEstado = new Map<string, Estado>();

/** Carga el ultimo estado conocido de cada componente para no re-alertar tras un reinicio. */
async function seed(): Promise<void> {
  try {
    const rows = await query<{ componente: string; estado: Estado }>(
      `SELECT DISTINCT ON (componente) componente, estado
         FROM health_log ORDER BY componente, ts DESC`
    );
    for (const r of rows) lastEstado.set(r.componente, r.estado);
  } catch {
    /* primera vez: tabla vacia */
  }
}

async function runCheck(notify: boolean): Promise<void> {
  const health = await refreshHealth();
  for (const c of health.componentes) {
    const prev = lastEstado.get(c.id);
    if (prev === c.estado) continue; // sin cambio -> nada

    // Registrar la transicion en la bitacora
    await query('INSERT INTO health_log(componente, estado, detalle) VALUES ($1, $2, $3)', [
      c.id, c.estado, c.detalle ?? c.resumen,
    ]);

    // Notificar solo transiciones significativas (y nunca en el arranque baseline)
    if (notify && prev !== undefined) {
      if (c.estado === 'fail' || (c.estado === 'warn' && prev === 'ok')) {
        await notifyHealthChange(c, prev, 'alerta');
      } else if (c.estado === 'ok' && (prev === 'fail' || prev === 'warn')) {
        await notifyHealthChange(c, prev, 'recuperacion');
      }
    }
    lastEstado.set(c.id, c.estado);
  }
}

export function startHealthMonitor(): void {
  const intervalMs = Math.max(30, env.HEALTH_POLL_SECONDS) * 1000;
  // Arranque: sembrar estado conocido y fijar baseline sin notificar.
  void seed()
    .then(() => runCheck(false))
    .then(() => {
      // eslint-disable-next-line no-console
      console.log(`🩺 Monitor de Salud del SIEM activo (cada ${env.HEALTH_POLL_SECONDS}s)`);
    })
    .catch((err) => console.error('Salud SIEM (arranque):', err instanceof Error ? err.message : err));

  setInterval(() => {
    void runCheck(true).catch((err) =>
      console.error('Salud SIEM (chequeo):', err instanceof Error ? err.message : err)
    );
  }, intervalMs);
}
