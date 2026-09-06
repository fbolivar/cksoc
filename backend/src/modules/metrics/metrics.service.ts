/**
 * Metricas de operacion del SOC sobre incidentes:
 *  - MTTD  (Mean Time To Detect):   tiempo de la alerta -> creacion del incidente
 *  - MTTA  (Mean Time To Acknowledge): creacion -> primera accion (nota/cambio de estado)
 *  - MTTR  (Mean Time To Resolve):  creacion -> resuelto/cerrado
 *  - Cumplimiento de SLA por severidad (objetivos de respuesta y resolucion)
 *  - Throughput (creados vs resueltos por dia) y backlog/aging.
 */
import { query } from '../../config/db';

export type Severity = 'baja' | 'media' | 'alta' | 'critica';

/** Objetivos de SLA por severidad (minutos). Respuesta = tiempo a primera accion. */
export const SLA_TARGETS: Record<Severity, { responseMin: number; resolutionMin: number }> = {
  critica: { responseMin: 30, resolutionMin: 240 }, // 30 min / 4 h
  alta: { responseMin: 60, resolutionMin: 480 }, //   1 h / 8 h
  media: { responseMin: 240, resolutionMin: 1440 }, //  4 h / 24 h
  baja: { responseMin: 480, resolutionMin: 4320 }, //   8 h / 72 h
};

const CLOSED = ['resuelto', 'cerrado'];

export type Disposition = 'verdadero_positivo' | 'falso_positivo' | 'prueba';

interface IncRow {
  id: string;
  severity: Severity;
  status: string;
  created_at: string;
  closed_at: string | null;
  alert_time: string | null;
  first_action: string | null;
  disposition: Disposition | null;
}

function minutesBetween(a: string, b: string): number {
  return (new Date(a).getTime() - new Date(b).getTime()) / 60000;
}

function avg(nums: number[]): number | null {
  if (nums.length === 0) return null;
  return Math.round((nums.reduce((s, n) => s + n, 0) / nums.length) * 10) / 10;
}

export interface SocMetrics {
  window: { days: number; from: string };
  counts: {
    total: number;
    abierto: number;
    en_curso: number;
    resuelto: number;
    cerrado: number;
    bySeverity: Record<string, number>;
  };
  /** Calidad: los FP/prueba se excluyen de MTTD/MTTA/MTTR/SLA para no distorsionarlos. */
  quality: {
    realTotal: number;                // verdaderos positivos + sin clasificar (lo medido)
    dispositions: { verdadero_positivo: number; falso_positivo: number; prueba: number; sin_clasificar: number };
    falsePositiveRate: number | null; // FP / (FP + verdaderos positivos) clasificados
    excludedFromMetrics: number;      // FP + prueba (fuera de los promedios)
  };
  mttd: { avgMinutes: number | null; count: number };
  mtta: { avgMinutes: number | null; count: number };
  mttr: { avgMinutes: number | null; count: number };
  sla: {
    targets: typeof SLA_TARGETS;
    overallPct: number | null;
    bySeverity: {
      severity: Severity;
      total: number;
      responseMet: number;
      responsePct: number | null;
      resolutionMet: number;
      resolutionEval: number;
      resolutionPct: number | null;
    }[];
  };
  aging: { openCount: number; oldestOpenHours: number | null; avgOpenAgeHours: number | null; openOver24h: number };
  throughput: { date: string; created: number; resolved: number }[];
}

export async function getSocMetrics(days = 30): Promise<SocMetrics> {
  const rows = await query<IncRow>(
    `SELECT i.id, i.severity, i.status, i.created_at, i.closed_at, i.disposition,
            (i.source->>'alertTime') AS alert_time,
            (SELECT min(n.created_at) FROM incident_notes n
               WHERE n.incident_id = i.id AND n.note NOT ILIKE 'Incidente creado%') AS first_action
       FROM incidents i
      WHERE i.created_at >= now() - ($1 || ' days')::interval`,
    [String(days)]
  );

  const now = Date.now();
  const counts = {
    total: rows.length,
    abierto: 0, en_curso: 0, resuelto: 0, cerrado: 0,
    bySeverity: { baja: 0, media: 0, alta: 0, critica: 0 } as Record<string, number>,
  };
  const mttd: number[] = [];
  const mtta: number[] = [];
  const mttr: number[] = [];

  // Acumuladores SLA por severidad
  const sev: Record<Severity, { total: number; responseMet: number; resolutionMet: number; resolutionEval: number }> = {
    baja: { total: 0, responseMet: 0, resolutionMet: 0, resolutionEval: 0 },
    media: { total: 0, responseMet: 0, resolutionMet: 0, resolutionEval: 0 },
    alta: { total: 0, responseMet: 0, resolutionMet: 0, resolutionEval: 0 },
    critica: { total: 0, responseMet: 0, resolutionMet: 0, resolutionEval: 0 },
  };

  const openAges: number[] = [];
  let openOver24h = 0;
  const disp = { verdadero_positivo: 0, falso_positivo: 0, prueba: 0, sin_clasificar: 0 };

  for (const r of rows) {
    if (r.status === 'abierto') counts.abierto++;
    else if (r.status === 'en_curso') counts.en_curso++;
    else if (r.status === 'resuelto') counts.resuelto++;
    else if (r.status === 'cerrado') counts.cerrado++;
    if (r.severity in counts.bySeverity) counts.bySeverity[r.severity]++;

    // Clasificación: los FP/prueba se cuentan pero NO entran a los promedios de
    // desempeño (si no, un falso positivo abierto 3 semanas infla el MTTR).
    if (r.disposition === 'verdadero_positivo') disp.verdadero_positivo++;
    else if (r.disposition === 'falso_positivo') disp.falso_positivo++;
    else if (r.disposition === 'prueba') disp.prueba++;
    else disp.sin_clasificar++;
    if (r.disposition === 'falso_positivo' || r.disposition === 'prueba') continue;

    const target = SLA_TARGETS[r.severity] ?? SLA_TARGETS.media;
    const s = sev[r.severity] ?? sev.media;
    s.total++;

    // MTTD: alerta -> creacion
    if (r.alert_time) {
      const d = minutesBetween(r.created_at, r.alert_time);
      if (d >= 0) mttd.push(d);
    }

    // MTTA: creacion -> primera accion (respuesta)
    let responseMinutes: number | null = null;
    if (r.first_action) {
      responseMinutes = minutesBetween(r.first_action, r.created_at);
      if (responseMinutes >= 0) mtta.push(responseMinutes);
    }
    // SLA de respuesta: cumple si respondio dentro del objetivo; si aun no hay
    // respuesta pero ya se paso el objetivo, incumple.
    const ageMin = (now - new Date(r.created_at).getTime()) / 60000;
    const responseElapsed = responseMinutes ?? ageMin;
    if (responseMinutes !== null || ageMin > target.responseMin) {
      if (responseElapsed <= target.responseMin) s.responseMet++;
    }

    // MTTR: creacion -> cierre
    if (CLOSED.includes(r.status) && r.closed_at) {
      const rm = minutesBetween(r.closed_at, r.created_at);
      if (rm >= 0) {
        mttr.push(rm);
        s.resolutionEval++;
        if (rm <= target.resolutionMin) s.resolutionMet++;
      }
    } else {
      // abierto/en_curso: aging
      openAges.push((now - new Date(r.created_at).getTime()) / 3600000);
      if (ageMin > 1440) openOver24h++;
    }
  }

  // SLA por severidad + global
  let slaMet = 0;
  let slaEval = 0;
  const bySeverity = (Object.keys(sev) as Severity[]).map((sv) => {
    const c = sev[sv];
    const responsePct = c.total > 0 ? Math.round((c.responseMet / c.total) * 1000) / 10 : null;
    const resolutionPct = c.resolutionEval > 0 ? Math.round((c.resolutionMet / c.resolutionEval) * 1000) / 10 : null;
    slaMet += c.responseMet + c.resolutionMet;
    slaEval += c.total + c.resolutionEval;
    return {
      severity: sv, total: c.total,
      responseMet: c.responseMet, responsePct,
      resolutionMet: c.resolutionMet, resolutionEval: c.resolutionEval, resolutionPct,
    };
  });
  const overallPct = slaEval > 0 ? Math.round((slaMet / slaEval) * 1000) / 10 : null;

  // Throughput por dia
  const created = await query<{ d: string; n: string }>(
    `SELECT to_char(date_trunc('day', created_at), 'YYYY-MM-DD') d, count(*) n
       FROM incidents WHERE created_at >= now() - ($1 || ' days')::interval
      GROUP BY 1 ORDER BY 1`,
    [String(days)]
  );
  const resolved = await query<{ d: string; n: string }>(
    `SELECT to_char(date_trunc('day', closed_at), 'YYYY-MM-DD') d, count(*) n
       FROM incidents WHERE closed_at IS NOT NULL AND closed_at >= now() - ($1 || ' days')::interval
      GROUP BY 1 ORDER BY 1`,
    [String(days)]
  );
  const tp = new Map<string, { created: number; resolved: number }>();
  for (const c of created) tp.set(c.d, { created: Number(c.n), resolved: 0 });
  for (const r of resolved) {
    const e = tp.get(r.d) ?? { created: 0, resolved: 0 };
    e.resolved = Number(r.n);
    tp.set(r.d, e);
  }
  const throughput = [...tp.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([date, v]) => ({ date, ...v }));

  const clasificados = disp.verdadero_positivo + disp.falso_positivo;
  const quality = {
    realTotal: disp.verdadero_positivo + disp.sin_clasificar,
    dispositions: disp,
    falsePositiveRate: clasificados > 0 ? Math.round((disp.falso_positivo / clasificados) * 1000) / 10 : null,
    excludedFromMetrics: disp.falso_positivo + disp.prueba,
  };

  return {
    window: { days, from: new Date(now - days * 86400000).toISOString() },
    counts,
    quality,
    mttd: { avgMinutes: avg(mttd), count: mttd.length },
    mtta: { avgMinutes: avg(mtta), count: mtta.length },
    mttr: { avgMinutes: avg(mttr), count: mttr.length },
    sla: { targets: SLA_TARGETS, overallPct, bySeverity },
    aging: {
      openCount: openAges.length,
      oldestOpenHours: openAges.length ? Math.round(Math.max(...openAges) * 10) / 10 : null,
      avgOpenAgeHours: avg(openAges),
      openOver24h,
    },
    throughput,
  };
}
