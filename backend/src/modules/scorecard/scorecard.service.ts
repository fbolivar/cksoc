/**
 * Scorecard de Exposición Externa — calificación A–F que agrega la postura externa
 * del cliente reutilizando módulos existentes (NO vuelve a consultar fuentes externas
 * de forma directa; llama a los servicios que ya cachean/consultan):
 *   - Superficie externa (ASM)      - Postura de correo (SPF/DKIM/DMARC)
 *   - Exposición de credenciales    - Riesgo digital / suplantación (DRP)
 *   - Exposición a ransomware (aparición en sitios de extorsión)
 * Pensado como "informe de lo que un atacante ve de ti".
 */
import { getOverview as asmOverview } from '../asm/asm.service';
import { getPosture } from '../email-posture/email-posture.service';
import { getSummary as credSummary } from '../credexp/credexp.service';
import { getOverview as drpOverview } from '../drp/drp.service';
import { getOverview as rwOverview } from '../ransomware/ransomware.service';

export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';
const clamp = (n: number): number => Math.max(0, Math.min(100, Math.round(n)));
function gradeOf(s: number): Grade { return s >= 90 ? 'A' : s >= 80 ? 'B' : s >= 70 ? 'C' : s >= 60 ? 'D' : 'F'; }

export interface ScoreCategory { key: string; label: string; score: number | null; grade: Grade | null; weight: number; resumen: string; hallazgos: string[] }
export interface ScorecardData { generatedAt: string; score: number; grade: Grade; categorias: ScoreCategory[]; resumenEjecutivo: string }

async function catAsm(): Promise<ScoreCategory> {
  const label = 'Superficie externa', weight = 20;
  try {
    const o = (await asmOverview()) as { hosts?: number; ips?: number; hallazgos?: { critica: number; alta: number; media: number; baja: number } };
    if (!o.hosts) return { key: 'asm', label, score: null, grade: null, weight, resumen: 'Sin escaneo de superficie aún.', hallazgos: [] };
    const h = o.hallazgos ?? { critica: 0, alta: 0, media: 0, baja: 0 };
    const score = clamp(100 - (h.critica * 25 + h.alta * 12 + h.media * 5 + h.baja));
    const hall: string[] = [];
    if (h.critica || h.alta) hall.push(`${h.critica} crítica(s) · ${h.alta} alta(s) en servicios expuestos`);
    if (h.media) hall.push(`${h.media} de severidad media`);
    if (!hall.length) hall.push(`Sin hallazgos de riesgo en la superficie expuesta`);
    return { key: 'asm', label, score, grade: gradeOf(score), weight, resumen: `${o.hosts} host(s) / ${o.ips ?? '?'} IP(s) expuestos a Internet`, hallazgos: hall };
  } catch { return { key: 'asm', label, score: null, grade: null, weight, resumen: 'No disponible', hallazgos: [] }; }
}

async function catEmail(): Promise<ScoreCategory> {
  const label = 'Postura de correo', weight = 25;
  try {
    const posture = (await getPosture()) as { domain: string; score: number; grade: string; checks: { key: string; grade: string }[] }[];
    if (!posture.length) return { key: 'email', label, score: null, grade: null, weight, resumen: 'Sin dominios configurados.', hallazgos: [] };
    const avg = clamp(posture.reduce((a, d) => a + (d.score ?? 0), 0) / posture.length);
    const hall: string[] = [];
    for (const d of posture) {
      const bad = (d.checks ?? []).filter((c) => c.grade === 'fail' || c.grade === 'missing').map((c) => c.key.toUpperCase());
      if (bad.length) hall.push(`${d.domain}: ${bad.join(', ')} sin aplicar`);
    }
    if (!hall.length) hall.push('SPF, DKIM, DMARC y MX correctos');
    return { key: 'email', label, score: avg, grade: gradeOf(avg), weight, resumen: `${posture.length} dominio(s) · puntaje medio ${avg}/100`, hallazgos: hall };
  } catch { return { key: 'email', label, score: null, grade: null, weight, resumen: 'No disponible', hallazgos: [] }; }
}

async function catCred(): Promise<ScoreCategory> {
  const label = 'Exposición de credenciales', weight = 20;
  try {
    const s = (await credSummary()) as { totalExpuestas?: number; cuentasCriticas?: number; topBrechas?: { title: string; cuentas: number }[] };
    const total = s.totalExpuestas ?? 0, crit = s.cuentasCriticas ?? 0;
    const score = clamp(100 - Math.min(50, total * 0.8) - crit * 3);
    const hall: string[] = [];
    if (total) hall.push(`${total} cuenta(s) en brechas de datos${crit ? ` · ${crit} con datos críticos` : ''}`);
    else hall.push('Sin credenciales expuestas detectadas');
    if (s.topBrechas?.[0]) hall.push(`Mayor brecha: ${s.topBrechas[0].title} (${s.topBrechas[0].cuentas})`);
    return { key: 'cred', label, score, grade: gradeOf(score), weight, resumen: `${total} cuenta(s) corporativa(s) expuesta(s)`, hallazgos: hall };
  } catch { return { key: 'cred', label, score: null, grade: null, weight, resumen: 'No disponible', hallazgos: [] }; }
}

async function catDrp(): Promise<ScoreCategory> {
  const label = 'Suplantación de marca (DRP)', weight = 20;
  try {
    const o = (await drpOverview()) as { severidad?: { critica: number; alta: number; media: number }; conMx?: number };
    const sev = o.severidad ?? { critica: 0, alta: 0, media: 0 };
    const mx = o.conMx ?? 0;
    const reg = sev.critica + sev.alta + sev.media;
    const score = clamp(100 - Math.min(75, sev.critica * 10 + sev.alta * 7 + sev.media * 3 + mx * 3));
    const hall: string[] = [];
    if (reg) hall.push(`${reg} dominio(s) parecido(s) registrado(s)`);
    if (mx) hall.push(`${mx} pueden enviar correo suplantando (con MX)`);
    if (!reg) hall.push('Sin dominios de suplantación registrados');
    return { key: 'drp', label, score, grade: gradeOf(score), weight, resumen: `${reg} dominio(s) de suplantación · ${mx} con correo activo`, hallazgos: hall };
  } catch { return { key: 'drp', label, score: null, grade: null, weight, resumen: 'No disponible', hallazgos: [] }; }
}

async function catRansom(): Promise<ScoreCategory> {
  const label = 'Exposición a ransomware', weight = 15;
  try {
    const o = await rwOverview(30);
    const k = o.kpis;
    const score = k.directos > 0 ? clamp(100 - k.directos * 60) : 100;
    const hall: string[] = [];
    if (k.directos > 0) hall.push(`⚠ El cliente aparece como víctima en ${k.directos} sitio(s) de extorsión`);
    else hall.push('Sin aparición del cliente en sitios de extorsión');
    hall.push(`Contexto: ${k.sectorHits} víctima(s) del sector · ${k.victimasPais} en el país`);
    return { key: 'ransomware', label, score, grade: gradeOf(score), weight, resumen: k.directos > 0 ? 'Aparición directa en extorsión' : 'Sin aparición directa', hallazgos: hall };
  } catch { return { key: 'ransomware', label, score: null, grade: null, weight, resumen: 'No disponible', hallazgos: [] }; }
}

let cache: { at: number; data: ScorecardData } | null = null;
const TTL = 5 * 60_000;

export async function getScorecard(): Promise<ScorecardData> {
  if (cache && Date.now() - cache.at < TTL) return cache.data;
  const categorias = await Promise.all([catAsm(), catEmail(), catCred(), catDrp(), catRansom()]);
  const valid = categorias.filter((c) => c.score != null);
  const totW = valid.reduce((a, c) => a + c.weight, 0) || 1;
  const score = clamp(valid.reduce((a, c) => a + (c.score as number) * c.weight, 0) / totW);
  const grade = gradeOf(score);
  const peores = [...valid].sort((a, b) => (a.score as number) - (b.score as number)).slice(0, 2).filter((c) => (c.score as number) < 80);
  const resumenEjecutivo = peores.length
    ? `Exposición externa ${grade} (${score}/100). Focos a mejorar: ${peores.map((c) => c.label.toLowerCase()).join(' y ')}.`
    : `Exposición externa ${grade} (${score}/100). Postura externa sólida; mantener el monitoreo.`;
  const data: ScorecardData = { generatedAt: new Date().toISOString(), score, grade, categorias, resumenEjecutivo };
  cache = { at: Date.now(), data };
  return data;
}

export function invalidateScorecard(): void { cache = null; }
