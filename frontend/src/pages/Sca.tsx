/**
 * Configuration Assessment (SCA): postura de hardening (CIS) por agente y las
 * principales brechas de configuracion con su remediacion.
 */
import { useEffect, useState } from 'react';
import { AxiosError } from 'axios';
import { ClipboardCheck, RefreshCw, Loader2, Server, Wrench } from 'lucide-react';
import { scaApi, scoreColor, type ScaData } from '@/lib/sca';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { KpiCard } from '@/components/shared/KpiCard';

export default function Sca() {
  const [data, setData] = useState<ScaData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<number | null>(null);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      setData(await scaApi.get());
    } catch (e) {
      setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo cargar SCA');
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => { load(); }, []);

  const r = data?.resumen;

  return (
    <div className="mx-auto max-w-7xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 hw-mono text-2xl font-bold tracking-tight">
            <ClipboardCheck className="h-6 w-6 text-neon" /> Configuration Assessment
          </h1>
          <p className="text-sm text-muted-foreground">
            Postura de hardening (CIS Benchmarks) evaluada por Wazuh SCA en cada activo
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={load} disabled={loading}>
          <RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} /> Actualizar
        </Button>
      </div>

      {error && <Card><CardContent className="p-4 text-sm text-amber-700">{error}</CardContent></Card>}

      {loading && !data ? (
        <p className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" /> Evaluando configuración…
        </p>
      ) : r && r.agentesEvaluados === 0 ? (
        <Card><CardContent className="py-12 text-center text-sm text-muted-foreground">
          Aún no hay evaluaciones SCA publicadas por los agentes.
        </CardContent></Card>
      ) : r && data && (
        <>
          {/* KPIs */}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
            <KpiCard label="Cumplimiento promedio" value={`${r.scorePromedio}%`} color={scoreColor(r.scorePromedio)} />
            <KpiCard label="Activos evaluados" value={r.agentesEvaluados} />
            <KpiCard label="Checks evaluados" value={r.totalChecks.toLocaleString('es-CO')} />
            <KpiCard label="Aprobados" value={r.pass.toLocaleString('es-CO')} color="#22c55e" />
            <KpiCard label="Fallidos" value={r.fail.toLocaleString('es-CO')} color="#ef4444" />
          </div>

          {/* Postura por activo */}
          <Card>
            <CardHeader><CardTitle className="text-muted-foreground">Postura de hardening por activo</CardTitle></CardHeader>
            <CardContent>
              <div className="space-y-3">
                {data.agentes.map((p) => (
                  <div key={`${p.agentId}-${p.policyId}`} className="space-y-1.5">
                    <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
                      <span className="flex items-center gap-1.5 font-mono text-xs">
                        <Server className="h-3.5 w-3.5 text-muted-foreground" />{p.agent}
                        <span className="text-muted-foreground/60">· {p.policy}</span>
                      </span>
                      <span className="tabular-nums text-xs text-muted-foreground">
                        <span style={{ color: '#22c55e' }}>{p.pass} ✓</span> ·{' '}
                        <span style={{ color: '#ef4444' }}>{p.fail} ✗</span> · {p.total} checks ·{' '}
                        <b style={{ color: scoreColor(p.score) }}>{p.score}%</b>
                      </span>
                    </div>
                    <div className="h-2.5 w-full overflow-hidden rounded-full bg-secondary">
                      <div className="h-full transition-all" style={{ width: `${p.score}%`, background: scoreColor(p.score) }} />
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Top brechas de configuracion */}
          <Card>
            <CardHeader><CardTitle className="flex items-center gap-2 text-muted-foreground">
              <Wrench className="h-4 w-4" /> Principales brechas de configuración (con remediación)
            </CardTitle></CardHeader>
            <CardContent>
              {data.topFallidos.length === 0 ? (
                <p className="py-4 text-center text-sm text-muted-foreground">Sin checks fallidos recientes registrados.</p>
              ) : (
                <div className="divide-y divide-border/40">
                  {data.topFallidos.map((c, i) => (
                    <div key={c.title} className="py-2.5">
                      <button onClick={() => setOpen(open === i ? null : i)} className="flex w-full items-start gap-3 text-left">
                        <span className="mt-0.5 inline-flex h-5 min-w-[2rem] items-center justify-center rounded bg-red-500/15 px-1.5 text-[11px] font-semibold text-red-400">
                          {c.count}
                        </span>
                        <span className="flex-1 text-sm">{c.title}</span>
                      </button>
                      {open === i && (c.remediation || c.rationale) && (
                        <div className="mt-2 ml-11 space-y-1.5 rounded-md border border-border/50 bg-secondary/30 p-3 text-xs">
                          {c.rationale && <p><span className="text-muted-foreground">Justificación: </span>{c.rationale}</p>}
                          {c.remediation && <p><span className="text-neon">Remediación: </span>{c.remediation}</p>}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
