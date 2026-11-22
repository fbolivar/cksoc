/**
 * Riesgo de Datos en Nube (M365) — DETECCIÓN (no backup) de operaciones masivas en
 * OneDrive/SharePoint desde la auditoría O365 del indexer Wazuh, por RÁFAGA por usuario:
 *   - Borrado masivo (ransomware en la nube / sabotaje)
 *   - Modificación/renombrado masivo (cifrado por ransomware)
 *   - Descarga masiva (exfiltración)
 *   - Compartición externa/anónima masiva
 * Umbrales por usuario (los totales del tenant son altos de forma normal). Solo lectura.
 */
import { getIndexerClient } from '../wazuh/wazuh.client';
import { env } from '../../config/env';
import { query } from '../../config/db';
import { logger } from '../../config/logger';

const INDEX = env.WAZUH_ALERTS_INDEX;
const RANGE: Record<string, string> = { '24h': 'now-24h', '7d': 'now-7d', '30d': 'now-30d' };
const gte = (r: string): string => RANGE[r] ?? 'now-24h';
const n = (v: string | undefined, d: number): number => { const x = Number(v); return Number.isFinite(x) && x > 0 ? x : d; };

const TH = {
  del: n(process.env.CLOUDDATA_DEL, 100),
  mod: n(process.env.CLOUDDATA_MOD, 300),
  dl: n(process.env.CLOUDDATA_DL, 500),
  share: n(process.env.CLOUDDATA_SHARE, 15),
  anon: n(process.env.CLOUDDATA_ANON, 5),
};
const OPS = {
  del: ['FileDeleted', 'FileRecycled', 'FileVersionsAllDeleted', 'FileDeletedFirstStageRecycleBin', 'FileDeletedSecondStageRecycleBin'],
  mod: ['FileModified', 'FileModifiedExtended', 'FileRenamed'],
  dl: ['FileDownloaded', 'FileSyncDownloadedFull'],
  share: ['SharingSet', 'SharingLinkCreated', 'SharingInvitationCreated', 'AddedToSecureLink', 'CompanyLinkCreated'],
  anon: ['AnonymousLinkCreated', 'AnonymousLinkUpdated'],
};
const SYS = /^(app@sharepoint|SHAREPOINT\\|NT AUTHORITY|Not Available|System)/i;

export type Sev = 'critica' | 'alta' | 'media';
export interface CdFinding { tipo: string; tipoLabel: string; user: string; count: number; umbral: number; sev: Sev }
export interface CdOverview {
  generatedAt: string; range: string; umbrales: typeof TH;
  kpis: { borrado: number; modificacion: number; descarga: number; comparticion: number; anonimo: number };
  hallazgos: CdFinding[];
}

interface TermsAgg { buckets: { key: string; doc_count: number }[] }

function agg(ops: string[], threshold: number) {
  return { filter: { terms: { 'data.office365.Operation': ops } }, aggs: { by: { terms: { field: 'data.office365.UserId', size: 50, min_doc_count: threshold } } } };
}
function sevOf(count: number, th: number): Sev { return count >= th * 3 ? 'critica' : count >= th * 2 ? 'alta' : 'media'; }

export async function getOverview(days = '24h'): Promise<CdOverview> {
  const body = {
    size: 0,
    query: { bool: { filter: [{ exists: { field: 'data.office365.Operation' } }, { range: { '@timestamp': { gte: gte(days) } } }] } },
    aggs: {
      del: agg(OPS.del, TH.del), mod: agg(OPS.mod, TH.mod), dl: agg(OPS.dl, TH.dl),
      share: agg(OPS.share, TH.share), anon: agg(OPS.anon, TH.anon),
    },
  };
  const hallazgos: CdFinding[] = [];
  try {
    const { data } = await getIndexerClient().post<{ aggregations: Record<string, { by: TermsAgg }> }>(`/${INDEX}/_search`, body);
    const a = data.aggregations;
    const push = (key: keyof typeof OPS, tipo: string, label: string, th: number) => {
      for (const b of a[key]?.by?.buckets ?? []) {
        if (SYS.test(b.key) || !b.key.includes('@')) continue;
        hallazgos.push({ tipo, tipoLabel: label, user: b.key, count: b.doc_count, umbral: th, sev: sevOf(b.doc_count, th) });
      }
    };
    push('del', 'borrado_masivo', 'Borrado masivo de archivos', TH.del);
    push('mod', 'modificacion_masiva', 'Modificación/renombrado masivo', TH.mod);
    push('dl', 'descarga_masiva', 'Descarga masiva (posible exfiltración)', TH.dl);
    push('share', 'comparticion_masiva', 'Compartición externa masiva', TH.share);
    push('anon', 'enlaces_anonimos', 'Creación masiva de enlaces anónimos', TH.anon);
  } catch (e) { logger.warn({ err: (e as Error).message }, 'clouddata: query'); }

  const rank = { critica: 0, alta: 1, media: 2 } as const;
  hallazgos.sort((x, y) => rank[x.sev] - rank[y.sev] || y.count - x.count);
  return {
    generatedAt: new Date().toISOString(), range: days, umbrales: TH,
    kpis: {
      borrado: hallazgos.filter((h) => h.tipo === 'borrado_masivo').length,
      modificacion: hallazgos.filter((h) => h.tipo === 'modificacion_masiva').length,
      descarga: hallazgos.filter((h) => h.tipo === 'descarga_masiva').length,
      comparticion: hallazgos.filter((h) => h.tipo === 'comparticion_masiva').length,
      anonimo: hallazgos.filter((h) => h.tipo === 'enlaces_anonimos').length,
    },
    hallazgos,
  };
}

// ─── dedup + alertas (borrado/modificación/exfil en 24h) ───
export async function ensureSchema(): Promise<void> {
  await query('CREATE TABLE IF NOT EXISTS clouddata_seen (k TEXT PRIMARY KEY, tipo TEXT, usr TEXT, first_seen TIMESTAMPTZ NOT NULL DEFAULT now())', []);
}
export async function findNew(): Promise<CdFinding[]> {
  await ensureSchema();
  const ov = await getOverview('24h');
  const watch = ov.hallazgos.filter((h) => h.tipo !== 'comparticion_masiva'); // alerta lo severo; compartición se ve en el panel
  const fresh: CdFinding[] = [];
  const day = new Date().toISOString().slice(0, 10);
  for (const h of watch) {
    const k = `${day}|${h.tipo}|${h.user}`.toLowerCase();
    const rows = await query('SELECT 1 FROM clouddata_seen WHERE k=$1', [k]);
    if (!rows.length) { await query('INSERT INTO clouddata_seen(k,tipo,usr) VALUES($1,$2,$3) ON CONFLICT DO NOTHING', [k, h.tipo, h.user]); fresh.push(h); }
  }
  return fresh;
}
export async function seedBaseline(): Promise<boolean> {
  await ensureSchema();
  const rows = await query<{ n: number }>('SELECT count(*)::int AS n FROM clouddata_seen', []);
  if ((rows[0]?.n ?? 0) > 0) return false;
  await findNew();
  logger.info('☁ Riesgo de datos en nube: baseline sembrado');
  return true;
}
