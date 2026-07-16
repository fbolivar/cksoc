/**
 * Métricas de operación del SOC: ¿qué tan bien opera el equipo?
 * MTTD/MTTA/MTTR, cumplimiento de SLA por severidad, throughput y backlog.
 */
import { useEffect, useState } from 'react';
import { Timer, Gauge, CheckCircle2, AlertTriangle, TrendingUp } from 'lucide-react';
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid, Legend,
} from 'recharts';
import { metricsApi, fmtDuration, type SocMetrics } from '@/lib/metrics';
import { tooltipStyle, CHART_GREEN, CHART_BLUE } from '@/components/dashboard/theme';

const SEV_LABEL: Record<string, string> = { baja: 'Baja', media: 'Media', alta: 'Alta', critica: 'Crítica' };

function Kpi({ icon: Icon, label, value, sub, tone }: {
  icon: typeof Timer; label: string; value: string; sub?: string; tone?: 'good' | 'warn' | 'bad';
}) {
  const color = tone === 'bad' ? 'text-destructive-foreground' : tone === 'warn' ? 'text-warn' : 'text-brand';
  return (
    <div className="glass rounded-lg p-4">
      <div className="flex items-center justify-between">
        <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{label}</p>
        <Icon className={`h-4 w-4 ${color}`} />
      </div>
      <p className={`mt-2 text-2xl font-semibold ${color}`}>{value}</p>
      {sub && <p className="text-[11px] text-muted-foreground">{sub}</p>}
    </div>
  );
}

export default function SocMetrics() {
  const [m, setM] = useState<SocMetrics | null>(null);
  const [days, setDays] = useState(30);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    metricsApi.soc(days).then(setM).catch(() => setM(null)).finally(() => setLoading(false));
  }, [days]);

  const slaTone = (pct: number | null) => (pct === null ? undefined : pct >= 90 ? 'good' : pct >= 70 ? 'warn' : 'bad');

  return (
    <div className="mx-auto max-w-6xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Métricas del SOC</h1>
          <p className="text-sm text-muted-foreground">Desempeño operativo sobre incidentes — MTTD, MTTA, MTTR y SLA</p>
        </div>
        <div className="flex gap-1">
          {[7, 30, 90].map((d) => (
            <button
              key={d}
              onClick={() => setDays(d)}
              className={`rounded-md px-3 py-1.5 text-sm ${days === d ? 'bg-primary text-primary-foreground' : 'bg-secondary text-muted-foreground hover:text-foreground'}`}
            >
              {d} días
            </button>
          ))}
        </div>
      </div>

      {loading || !m ? (
        <div className="glass rounded-lg p-10 text-center text-sm text-muted-foreground">
          {loading ? 'Calculando…' : 'Sin datos'}
        </div>
      ) : (
        <>
          {/* KPIs principales */}
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <Kpi icon={Timer} label="MTTD · detección" value={fmtDuration(m.mttd.avgMinutes)}
              sub={`${m.mttd.count} con dato (alerta→incidente)`} />
            <Kpi icon={Gauge} label="MTTA · 1ª respuesta" value={fmtDuration(m.mtta.avgMinutes)}
              sub={`${m.mtta.count} incidentes`} />
            <Kpi icon={CheckCircle2} label="MTTR · resolución" value={fmtDuration(m.mttr.avgMinutes)}
              sub={`${m.mttr.count} resueltos`} />
            <Kpi icon={TrendingUp} label="Cumplimiento SLA" value={m.sla.overallPct === null ? '—' : `${m.sla.overallPct}%`}
              sub={`ventana de ${m.window.days} días`} tone={slaTone(m.sla.overallPct)} />
          </div>

          {/* Backlog / aging */}
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <Kpi icon={AlertTriangle} label="Incidentes abiertos" value={String(m.counts.abierto + m.counts.en_curso)}
              sub={`${m.counts.abierto} abiertos · ${m.counts.en_curso} en curso`} tone={m.counts.abierto + m.counts.en_curso > 0 ? 'warn' : 'good'} />
            <Kpi icon={AlertTriangle} label="Abiertos > 24h" value={String(m.aging.openOver24h)}
              sub="fuera de ventana rápida" tone={m.aging.openOver24h > 0 ? 'bad' : 'good'} />
            <Kpi icon={Timer} label="Más antiguo abierto" value={m.aging.oldestOpenHours === null ? '—' : fmtDuration(m.aging.oldestOpenHours * 60)}
              sub="antigüedad del backlog" />
            <Kpi icon={CheckCircle2} label="Resueltos" value={String(m.counts.resuelto + m.counts.cerrado)}
              sub={`de ${m.counts.total} en la ventana`} tone="good" />
          </div>

          {/* Throughput */}
          <div className="glass rounded-lg p-4">
            <h3 className="mb-3 text-sm font-semibold">Flujo de incidentes · creados vs resueltos</h3>
            {m.throughput.length === 0 ? (
              <p className="py-8 text-center text-sm text-muted-foreground">Sin actividad en la ventana.</p>
            ) : (
              <ResponsiveContainer width="100%" height={240}>
                <BarChart data={m.throughput}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                  <XAxis dataKey="date" tick={{ fontSize: 11, fill: '#9fb3aa' }} />
                  <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: '#9fb3aa' }} />
                  <Tooltip contentStyle={tooltipStyle} />
                  <Legend wrapperStyle={{ fontSize: 12 }} />
                  <Bar dataKey="created" name="Creados" fill={CHART_BLUE} radius={[3, 3, 0, 0]} />
                  <Bar dataKey="resolved" name="Resueltos" fill={CHART_GREEN} radius={[3, 3, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>

          {/* SLA por severidad */}
          <div className="glass overflow-hidden rounded-lg">
            <h3 className="border-b border-border/60 px-4 py-3 text-sm font-semibold">Cumplimiento de SLA por severidad</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border/50 text-left text-xs text-muted-foreground">
                    <th className="px-4 py-2 font-medium">Severidad</th>
                    <th className="px-4 py-2 font-medium">Objetivo respuesta</th>
                    <th className="px-4 py-2 font-medium">Objetivo resolución</th>
                    <th className="px-4 py-2 font-medium">% Respuesta</th>
                    <th className="px-4 py-2 font-medium">% Resolución</th>
                    <th className="px-4 py-2 font-medium">Incidentes</th>
                  </tr>
                </thead>
                <tbody>
                  {m.sla.bySeverity.map((s) => {
                    const t = m.sla.targets[s.severity];
                    const pctCell = (pct: number | null) =>
                      pct === null ? <span className="text-muted-foreground">—</span> : (
                        <span className={pct >= 90 ? 'text-brand' : pct >= 70 ? 'text-warn' : 'text-destructive-foreground'}>{pct}%</span>
                      );
                    return (
                      <tr key={s.severity} className="border-b border-border/30">
                        <td className="px-4 py-2">{SEV_LABEL[s.severity]}</td>
                        <td className="px-4 py-2 text-xs text-muted-foreground">{fmtDuration(t.responseMin)}</td>
                        <td className="px-4 py-2 text-xs text-muted-foreground">{fmtDuration(t.resolutionMin)}</td>
                        <td className="px-4 py-2">{pctCell(s.responsePct)}</td>
                        <td className="px-4 py-2">{pctCell(s.resolutionPct)}</td>
                        <td className="px-4 py-2 text-muted-foreground">{s.total}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          <p className="text-center text-[11px] text-muted-foreground/70">
            MTTD requiere que el incidente se haya escalado desde una alerta (captura el tiempo de la alerta). MTTA = tiempo
            hasta la primera acción del analista. MTTR = tiempo hasta resolver/cerrar. Objetivos de SLA: crítica 30 min/4 h ·
            alta 1 h/8 h · media 4 h/24 h · baja 8 h/72 h.
          </p>
        </>
      )}
    </div>
  );
}
