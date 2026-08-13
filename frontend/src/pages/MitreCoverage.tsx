/**
 * Cobertura de Detección MITRE ATT&CK: por cada táctica, cuántas técnicas has
 * DETECTADO (observadas en alertas) frente al total del marco ATT&CK. Revela los
 * puntos ciegos — tácticas donde no tienes visibilidad.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { AxiosError } from 'axios';
import { Grid3x3, RefreshCw, Loader2, EyeOff, ShieldCheck } from 'lucide-react';
import { mitreApi, TACTIC_ES, type CoverageData } from '@/lib/mitre';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

const DAYS = [30, 90, 180];

function covColor(pct: number, detected: number): string {
  if (detected === 0) return '#dc2626';
  if (pct >= 20) return '#059669';
  if (pct >= 8) return '#ca8a04';
  return '#ea580c';
}

export default function MitreCoverage() {
  const [days, setDays] = useState(90);
  const [data, setData] = useState<CoverageData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const seq = useRef(0);
  const load = useCallback(async (d: number) => {
    const my = ++seq.current;
    setLoading(true); setError(null);
    try {
      const res = await mitreApi.coverage(d);
      if (my === seq.current) setData(res);
    } catch (e) {
      if (my === seq.current) { setData(null); setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo cargar la cobertura'); }
    } finally {
      if (my === seq.current) setLoading(false);
    }
  }, []);
  useEffect(() => { void load(days); }, [days, load]);

  const blind = (data?.tactics ?? []).filter((t) => t.detected === 0);
  const maxTotal = Math.max(1, ...(data?.tactics ?? []).map((t) => t.total));

  return (
    <div className="mx-auto max-w-5xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
            <Grid3x3 className="h-6 w-6 text-neon" /> Cobertura de Detección · MITRE ATT&CK
          </h1>
          <p className="text-sm text-muted-foreground">Qué técnicas detectas vs. el marco ATT&CK — dónde estás ciego</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex overflow-hidden rounded-md border border-input">
            {DAYS.map((d) => (
              <button key={d} onClick={() => setDays(d)} className={`px-3 py-1.5 text-xs ${days === d ? 'bg-secondary font-semibold text-foreground' : 'text-muted-foreground hover:bg-secondary/50'}`}>{d}d</button>
            ))}
          </div>
          <Button variant="outline" size="sm" onClick={() => void load(days)} disabled={loading}>
            <RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} />
          </Button>
        </div>
      </div>

      {error && <Card><CardContent className="p-4 text-sm text-amber-700">{error}</CardContent></Card>}

      {/* KPIs */}
      <div className="grid gap-3 sm:grid-cols-3">
        <Card><CardContent className="p-4"><p className="flex items-center gap-1.5 text-xs text-muted-foreground"><ShieldCheck className="h-3.5 w-3.5" /> Tácticas con cobertura</p><p className="text-2xl font-bold tabular-nums">{data ? `${data.tacticsCovered}/${data.tacticsTotal}` : '—'}</p></CardContent></Card>
        <Card><CardContent className="p-4"><p className="flex items-center gap-1.5 text-xs text-muted-foreground"><EyeOff className="h-3.5 w-3.5" /> Tácticas ciegas</p><p className="text-2xl font-bold tabular-nums text-rose-600">{data?.tacticsBlind ?? '—'}</p></CardContent></Card>
        <Card><CardContent className="p-4"><p className="text-xs text-muted-foreground">Técnicas detectadas</p><p className="text-2xl font-bold tabular-nums">{data?.techniquesDetected ?? '—'}</p></CardContent></Card>
      </div>

      {/* Puntos ciegos */}
      {blind.length > 0 && (
        <Card className="border-rose-500/30 bg-rose-500/[0.04]">
          <CardContent className="p-4">
            <p className="mb-2 flex items-center gap-2 text-sm font-semibold text-rose-600"><EyeOff className="h-4 w-4" /> Puntos ciegos: tácticas sin ninguna detección ({days} días)</p>
            <div className="flex flex-wrap gap-2">
              {blind.map((t) => (
                <span key={t.tactic} className="rounded-md border border-rose-500/30 bg-rose-500/10 px-2 py-1 text-xs text-rose-700">
                  {TACTIC_ES[t.tactic] ?? t.tactic} <span className="text-rose-500/70">(0/{t.total})</span>
                </span>
              ))}
            </div>
            <p className="mt-2 text-[11px] text-muted-foreground">No has detectado ninguna técnica de estas tácticas. Puede faltar telemetría/reglas, o simplemente no ha ocurrido actividad. Prioriza reglas para las relevantes a tu entorno.</p>
          </CardContent>
        </Card>
      )}

      {/* Cobertura por táctica */}
      <Card>
        <CardContent className="p-4">
          <p className="mb-3 text-sm font-semibold">Cobertura por táctica (peor primero)</p>
          {loading && !data ? (
            <p className="flex items-center gap-2 py-8 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Calculando…</p>
          ) : !data ? null : (
            <div className="space-y-2.5">
              {data.tactics.map((t) => {
                const color = covColor(t.coverage, t.detected);
                return (
                  <div key={t.tactic} className="flex items-center gap-3">
                    <div className="w-44 shrink-0">
                      <p className="truncate text-xs font-medium" title={t.tactic}>{TACTIC_ES[t.tactic] ?? t.tactic}</p>
                      <p className="text-[10px] text-muted-foreground">{t.detected}/{t.total} técnicas · {t.alerts.toLocaleString('es-CO')} alertas</p>
                    </div>
                    <div className="relative h-5 flex-1 overflow-hidden rounded bg-secondary/40">
                      {/* barra proporcional al tamaño de la táctica, rellena por lo detectado */}
                      <span className="absolute inset-y-0 left-0 rounded bg-muted-foreground/10" style={{ width: `${(t.total / maxTotal) * 100}%` }} />
                      <span className="absolute inset-y-0 left-0 rounded" style={{ width: `${(t.detected / maxTotal) * 100}%`, background: color }} />
                    </div>
                    <span className="w-12 shrink-0 text-right text-xs font-semibold tabular-nums" style={{ color }}>{t.coverage}%</span>
                  </div>
                );
              })}
            </div>
          )}
          <p className="mt-3 text-[11px] text-muted-foreground/70">
            "Cobertura observada": técnicas efectivamente detectadas en tus alertas en el rango, sobre el catálogo completo de ATT&CK (incluye sub-técnicas, por eso los % son bajos). La señal clave son las tácticas ciegas y la cobertura relativa, no el porcentaje absoluto.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
