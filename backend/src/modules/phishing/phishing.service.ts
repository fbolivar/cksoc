/**
 * Factor humano: campañas de phishing / concienciación. Registra resultados
 * (enviados, clics, reportados, % capacitados) y calcula la postura del dominio
 * "factor_humano" del Resumen Ejecutivo, que hasta ahora estaba sin fuente.
 */
import { query } from '../../config/db';

export interface Campaign {
  id: string;
  name: string;
  run_date: string;
  sent: number;
  clicked: number;
  reported: number;
  trained_pct: number;
  note: string | null;
  created_at: string;
}

export interface HumanFactor {
  clickRate: number;    // % que hizo clic
  reportRate: number;   // % que reportó el phishing
  trainedPct: number;   // % capacitado (promedio ponderado)
  posture: number;      // 0-100
  totalSent: number;
  campaigns: number;
  lastRun: string | null;
}

export async function listCampaigns(): Promise<Campaign[]> {
  return query<Campaign>('SELECT id, name, run_date, sent, clicked, reported, trained_pct, note, created_at FROM phishing_campaigns ORDER BY run_date DESC, created_at DESC LIMIT 200');
}

export async function createCampaign(input: { name: string; runDate: string; sent: number; clicked: number; reported: number; trainedPct: number; note?: string }, userId: string): Promise<Campaign> {
  const clamp = (n: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, Math.round(n) || 0));
  const sent = clamp(input.sent, 0, 1_000_000);
  const rows = await query<Campaign>(
    `INSERT INTO phishing_campaigns (name, run_date, sent, clicked, reported, trained_pct, note, created_by)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
     RETURNING id, name, run_date, sent, clicked, reported, trained_pct, note, created_at`,
    [input.name.trim().slice(0, 200), input.runDate, sent, Math.min(clamp(input.clicked, 0, sent), sent), Math.min(clamp(input.reported, 0, sent), sent), clamp(input.trainedPct, 0, 100), input.note?.trim() || null, userId],
  );
  return rows[0];
}

export async function deleteCampaign(id: string): Promise<void> {
  await query('DELETE FROM phishing_campaigns WHERE id = $1', [id]);
}

/** Métricas agregadas de los últimos 12 meses (o null si no hay campañas). */
export async function getHumanFactor(): Promise<HumanFactor | null> {
  const rows = await query<{ sent: string; clicked: string; reported: string; wtrained: string; n: string; last: string | null }>(
    `SELECT COALESCE(SUM(sent),0) AS sent, COALESCE(SUM(clicked),0) AS clicked,
            COALESCE(SUM(reported),0) AS reported,
            COALESCE(SUM(trained_pct::numeric * sent),0) AS wtrained,
            COUNT(*) AS n, MAX(run_date) AS last
     FROM phishing_campaigns WHERE run_date > now() - interval '12 months'`,
  );
  const r = rows[0];
  const sent = Number(r?.sent ?? 0);
  const n = Number(r?.n ?? 0);
  if (!n || sent === 0) return null;
  const clicked = Number(r.clicked), reported = Number(r.reported);
  const clickRate = Math.round((clicked / sent) * 1000) / 10;
  const reportRate = Math.round((reported / sent) * 1000) / 10;
  const trainedPct = Math.round(Number(r.wtrained) / sent);
  // Postura: menos clics es mejor; más reportes y capacitación suben.
  const posture = Math.max(0, Math.min(100, Math.round((100 - clickRate) * 0.5 + reportRate * 0.3 + trainedPct * 0.2)));
  return { clickRate, reportRate, trainedPct, posture, totalSent: sent, campaigns: n, lastRun: r.last };
}
