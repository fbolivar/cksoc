/**
 * Resumen diario por correo (8 AM America/Bogota por defecto, configurable).
 * Incluye: conteo por severidad, alertas Altas (7-11) agrupadas por regla/agente,
 * top origenes de ataque (geo) e IPs bloqueadas en el dia.
 */
import cron from 'node-cron';
import { query } from '../../config/db';
import { env } from '../../config/env';
import { getIndexerClient } from '../wazuh/wazuh.client';
import { getSummary } from '../wazuh/wazuh.service';
import { getAttackGeo } from '../attacks/attacks.service';
import { getSettings, sendCapped, shell } from './notify.engine';

const esc = (s: string) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const fmt = (n: number) => n.toLocaleString('es-CO');

interface DigestData {
  fecha: string;
  total: number;
  byBand: { baja: number; media: number; alta: number; critica: number };
  topRules: { rule: string; level: number; agent: string; count: number }[];
  topOrigins: { country: string; city: string; count: number }[];
  blocked: { ip: string; usuario: string }[];
}

// Ruido benigno consistente con los dashboards: sin esto el digest diario a Telegram
// lo encabeza "Integrity checksum changed ×17.423" (FIM 550) y sepulta la señal real.
const DIGEST_NOISE: unknown[] = [
  { terms: { 'rule.id': ['81633', '80792', '550', '752', '91578', '100205', '100207', '100700', '5501'] } }, // SonicWall app-passed, audit systemd, FIM checksum, registry, O365 MailItemsAccessed
  { terms: { 'rule.groups': ['sca', 'vulnerability-detector'] } },
  // 100600 benigno (exfil interna/DVR/relays HexDesk). El externo real se conserva.
  {
    bool: {
      filter: [
        { term: { 'rule.id': '100600' } },
        {
          bool: {
            should: [
              { prefix: { 'data.dstip': '192.168.' } }, { prefix: { 'data.dstip': '10.' } }, { prefix: { 'data.dstip': '172.' } },
              { terms: { 'data.dstip': ['40.160.225.24', '209.250.254.15'] } }, { term: { 'data.srcip': '192.168.0.31' } },
            ],
            minimum_should_match: 1,
          },
        },
      ],
    },
  },
];

async function collect(): Promise<DigestData> {
  const client = getIndexerClient();
  const summary = await getSummary('24h');

  // Altas (7-11) agrupadas por regla + agente principal (excluyendo el ruido benigno).
  const { data } = await client.post<{
    aggregations: { r: { buckets: { key: string; doc_count: number; lvl: { value: number }; ag: { buckets: { key: string }[] } }[] } };
  }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
    size: 0,
    query: { bool: { filter: [{ range: { timestamp: { gte: 'now-24h' } } }, { range: { 'rule.level': { gte: 7, lte: 11 } } }], must_not: DIGEST_NOISE } },
    aggs: { r: { terms: { field: 'rule.description', size: 12 }, aggs: { lvl: { max: { field: 'rule.level' } }, ag: { terms: { field: 'agent.name', size: 1 } } } } },
  });
  const topRules = data.aggregations.r.buckets.map((b) => ({
    rule: b.key, level: Math.round(b.lvl.value), agent: b.ag.buckets[0]?.key ?? '—', count: b.doc_count,
  }));

  const origins = await getAttackGeo(24).catch(() => []);
  const topOrigins = origins.slice(0, 8).map((o) => ({ country: o.country, city: o.city, count: o.count }));

  const blockedRows = await query<{ ip: string; usuario_email: string }>(
    `SELECT ip, usuario_email FROM block_actions
      WHERE accion='block' AND resultado='success' AND created_at::date = (now() AT TIME ZONE $1)::date`,
    [env.DIGEST_TZ]
  );

  return {
    fecha: new Date().toLocaleDateString('es-CO', { timeZone: env.DIGEST_TZ, dateStyle: 'full' }),
    total: summary.total,
    byBand: summary.byBand,
    topRules,
    topOrigins,
    blocked: blockedRows.map((b) => ({ ip: b.ip, usuario: b.usuario_email ?? '—' })),
  };
}

function digestHtml(d: DigestData): string {
  const kpi = (v: number, l: string, c: string) =>
    `<td style="padding:10px;border:1px solid #1d2b25;text-align:center"><div style="font-size:20px;font-weight:800;color:${c}">${fmt(v)}</div><div style="font-size:10px;color:#9fb3aa">${l}</div></td>`;
  const sevTable = `<table style="width:100%;border-collapse:collapse;margin:8px 0 18px"><tr>
    ${kpi(d.total, 'TOTAL 24H', '#e6f2ec')}${kpi(d.byBand.critica, 'CRITICAS', '#ef4444')}
    ${kpi(d.byBand.alta, 'ALTAS', '#f97316')}${kpi(d.byBand.media, 'MEDIAS', '#eab308')}</tr></table>`;

  const rulesRows = d.topRules.length
    ? d.topRules.map((r) => `<tr><td style="padding:4px 6px;border-bottom:1px solid #16241d">${esc(r.rule).slice(0, 50)}</td><td style="padding:4px 6px;border-bottom:1px solid #16241d;text-align:center">${r.level}</td><td style="padding:4px 6px;border-bottom:1px solid #16241d">${esc(r.agent)}</td><td style="padding:4px 6px;border-bottom:1px solid #16241d;text-align:right">${fmt(r.count)}</td></tr>`).join('')
    : '<tr><td colspan="4" style="padding:8px;color:#9fb3aa">Sin alertas Altas en el periodo</td></tr>';

  const origRows = d.topOrigins.length
    ? d.topOrigins.map((o) => `<tr><td style="padding:4px 6px;border-bottom:1px solid #16241d">${esc(o.country)}${o.city ? ' · ' + esc(o.city) : ''}</td><td style="padding:4px 6px;border-bottom:1px solid #16241d;text-align:right">${fmt(o.count)}</td></tr>`).join('')
    : '<tr><td colspan="2" style="padding:8px;color:#9fb3aa">Sin origenes con IP publica</td></tr>';

  const blockedHtml = d.blocked.length
    ? `<p style="font-size:12px;color:#9fb3aa;margin:18px 0 6px">IPs BLOQUEADAS HOY (${d.blocked.length})</p><p style="font-size:12px">${d.blocked.map((b) => esc(b.ip)).join(', ')}</p>`
    : `<p style="font-size:12px;color:#9fb3aa;margin:18px 0 6px">No se bloquearon IPs hoy.</p>`;

  const body = `
    <p style="font-size:16px;font-weight:700;color:#34d399;margin:0 0 2px">Resumen diario de seguridad</p>
    <p style="font-size:12px;color:#9fb3aa;margin:0 0 14px">${esc(d.fecha)}</p>
    ${sevTable}
    <p style="font-size:12px;color:#9fb3aa;margin:0 0 6px">ALERTAS ALTAS (NIVEL 7-11) POR REGLA</p>
    <table style="width:100%;border-collapse:collapse;font-size:12px">
      <tr style="color:#9fb3aa;text-align:left"><th style="padding:4px 6px">Regla</th><th style="padding:4px 6px">Nivel</th><th style="padding:4px 6px">Agente</th><th style="padding:4px 6px;text-align:right">Conteo</th></tr>
      ${rulesRows}
    </table>
    <p style="font-size:12px;color:#9fb3aa;margin:18px 0 6px">TOP ORIGENES DE ATAQUE</p>
    <table style="width:100%;border-collapse:collapse;font-size:12px">${origRows}</table>
    ${blockedHtml}
    <a href="${env.PUBLIC_DASHBOARD_URL}" style="display:inline-block;margin-top:18px;background:#1f7a4d;color:#fff;text-decoration:none;padding:10px 18px;border-radius:8px;font-size:13px">Abrir el dashboard</a>`;
  return shell(`Resumen diario ${d.fecha}`, '#1f7a4d', body);
}

/** Construye y envia el resumen diario. */
export async function sendDailyDigest(): Promise<boolean> {
  const settings = await getSettings();
  if (settings.recipients.length === 0) return false;
  const d = await collect();
  const html = digestHtml(d);
  const fechaCorta = new Date().toLocaleDateString('es-CO', { timeZone: env.DIGEST_TZ });
  const text = `Resumen diario HexWatch ${fechaCorta}\nTotal 24h: ${d.total} | Criticas: ${d.byBand.critica} | Altas: ${d.byBand.alta}\nIPs bloqueadas hoy: ${d.blocked.length}`;
  return sendCapped(settings.recipients, `[HexWatch] Resumen diario - ${fechaCorta}`, html, text, { tipo: 'digest' });
}

/** True si ya se envio un digest en las ultimas 23h. */
async function digestAlreadySentToday(): Promise<boolean> {
  const rows = await query<{ id: string }>(
    `SELECT id FROM notification_log WHERE tipo='digest' AND status='sent' AND created_at > now() - interval '23 hours' LIMIT 1`
  );
  return rows.length > 0;
}

function bogotaHour(): number {
  return Number(new Date().toLocaleString('en-US', { timeZone: env.DIGEST_TZ, hour: '2-digit', hour12: false }));
}

export function startDigestScheduler(): void {
  // Cada hora en punto; dispara solo a la hora configurada (TZ Bogota).
  cron.schedule('0 * * * *', async () => {
    try {
      const settings = await getSettings();
      if (!settings.digestEnabled) return;
      if (bogotaHour() !== settings.digestHour) return;
      if (await digestAlreadySentToday()) return;
      await sendDailyDigest();
      // eslint-disable-next-line no-console
      console.log('📧 Resumen diario enviado');
    } catch (err) {
      console.error('Error en resumen diario:', err instanceof Error ? err.message : err);
    }
  }, { timezone: env.DIGEST_TZ });
  // eslint-disable-next-line no-console
  console.log(`📧 Scheduler de resumen diario activo (TZ ${env.DIGEST_TZ})`);
}
