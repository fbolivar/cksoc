/**
 * MITRE ATT&CK (vista unificada, 2 pestañas):
 *  - Actividad: matriz tipo Navigator (tácticas/técnicas observadas con heatmap) +
 *    técnicas de mayor riesgo. Responde "¿qué estoy viendo?".
 *  - Cobertura: técnicas detectadas vs el marco completo, con puntos ciegos.
 *    Responde "¿dónde estoy ciego?".
 * Ambas consumen mitreApi (misma fuente); antes eran dos entradas de menú.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { AxiosError } from 'axios';
import { Crosshair, RefreshCw, Loader2, AlertTriangle, EyeOff, ShieldCheck } from 'lucide-react';
import { mitreApi, TACTIC_ORDER, TACTIC_ES, type MitreData, type MitreTechnique, type CoverageData } from '@/lib/mitre';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { RangeTabs, RANGE_24_7_30 } from '@/components/shared/RangeTabs';
import { KpiCard } from '@/components/shared/KpiCard';

type Tab = 'actividad' | 'cobertura';

export default function Mitre() {
  const [tab, setTab] = useState<Tab>('actividad');
  return (
    <div className="mx-auto max-w-[1400px] space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 hw-mono text-2xl font-bold tracking-tight">
            <Crosshair className="h-6 w-6 text-neon" /> MITRE ATT&CK
          </h1>
          <p className="text-sm text-muted-foreground">
            {tab === 'actividad'
              ? 'Tácticas y técnicas adversarias detectadas, mapeadas al framework'
              : 'Qué técnicas detectas vs. el marco ATT&CK — dónde estás ciego'}
          </p>
        </div>
        <div className="flex overflow-hidden rounded-md border border-input">
          {(['actividad', 'cobertura'] as Tab[]).map((t) => (
            <button key={t} onClick={() => setTab(t)}
              className={`px-3.5 py-1.5 text-sm capitalize ${tab === t ? 'bg-secondary font-semibold text-foreground' : 'text-muted-foreground hover:bg-secondary/50'}`}>
              {t === 'actividad' ? 'Actividad' : 'Cobertura'}
            </button>
          ))}
        </div>
      </div>

      {tab === 'actividad' ? <ActivityView /> : <CoverageView />}
    </div>
  );
}

/* ------------------------------- Actividad ------------------------------- */

type Range = '24h' | '7d' | '30d';
const HOURS: Record<Range, number> = { '24h': 24, '7d': 168, '30d': 720 };

function sevBorder(level: number): string {
  if (level >= 12) return '#ef4444';
  if (level >= 8) return '#f97316';
  if (level >= 5) return '#eab308';
  return 'transparent';
}

function ActivityView() {
  const [range, setRange] = useState<Range>('7d');
  const [data, setData] = useState<MitreData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function load(r: Range) {
    setLoading(true);
    setError(null);
    try {
      setData(await mitreApi.get(HOURS[r]));
    } catch (e) {
      setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo cargar MITRE ATT&CK');
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => { load(range); }, [range]);

  const columns = useMemo(() => {
    if (!data) return [];
    const countByTactic = new Map(data.tactics.map((t) => [t.tactic, t.count]));
    const present = TACTIC_ORDER.filter((t) => countByTactic.has(t));
    for (const t of data.tactics) if (!present.includes(t.tactic)) present.push(t.tactic);
    return present.map((tactic) => ({
      tactic,
      count: countByTactic.get(tactic) ?? 0,
      techniques: data.techniques.filter((te) => te.tactics.includes(tactic)).sort((a, b) => b.count - a.count),
    }));
  }, [data]);

  const maxCount = useMemo(() => Math.max(1, ...(data?.techniques ?? []).map((t) => t.count)), [data]);
  const riesgo = useMemo(
    () => [...(data?.techniques ?? [])].sort((a, b) => b.maxLevel - a.maxLevel || b.count - a.count).slice(0, 8),
    [data]
  );
  const heat = (count: number) => Math.log(count + 1) / Math.log(maxCount + 1);

  return (
    <>
      <div className="flex items-center justify-end gap-2">
        <RangeTabs value={range} onChange={setRange} options={RANGE_24_7_30} />
        <Button variant="outline" size="sm" onClick={() => load(range)} disabled={loading}>
          <RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} /> Actualizar
        </Button>
      </div>

      {error && <Card><CardContent className="p-4 text-sm text-amber-700">{error}</CardContent></Card>}

      {loading && !data ? (
        <p className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" /> Cargando matriz ATT&CK…
        </p>
      ) : data && (
        <>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <KpiCard label="Eventos mapeados a ATT&CK" value={data.total.toLocaleString('es-CO')} />
            <KpiCard label="Técnicas distintas" value={data.tecnicasDistintas} />
            <KpiCard label="Tácticas observadas" value={`${columns.length} / 14`} />
            <KpiCard label="Técnica más activa" value={data.techniques[0]?.id ?? '—'} />
          </div>

          <Card>
            <CardHeader><CardTitle className="flex items-center gap-2 text-muted-foreground">
              <AlertTriangle className="h-4 w-4 text-amber-400" /> Técnicas de mayor riesgo (por severidad)
            </CardTitle></CardHeader>
            <CardContent>
              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
                {riesgo.map((t) => (
                  <a key={t.id} href={`https://attack.mitre.org/techniques/${t.id.replace('.', '/')}/`} target="_blank" rel="noreferrer"
                    className="rounded-md border-l-2 bg-secondary/40 p-2.5 transition-colors hover:bg-secondary"
                    style={{ borderColor: sevBorder(t.maxLevel) }}>
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs text-neon">{t.id}</span>
                      <span className="text-[10px] text-muted-foreground">nivel {t.maxLevel}</span>
                    </div>
                    <p className="truncate text-xs">{t.name}</p>
                    <p className="text-[10px] text-muted-foreground">{t.count.toLocaleString('es-CO')} eventos</p>
                  </a>
                ))}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0">
              <CardTitle className="text-muted-foreground">Matriz ATT&CK · tácticas y técnicas observadas</CardTitle>
              <div className="flex items-center gap-2 text-[10px] text-muted-foreground">
                <span>menos</span>
                <span className="h-3 w-6 rounded" style={{ background: 'rgba(220,38,38,0.35)' }} />
                <span className="h-3 w-6 rounded" style={{ background: 'rgba(220,38,38,0.58)' }} />
                <span className="h-3 w-6 rounded" style={{ background: 'rgba(220,38,38,0.82)' }} />
                <span>más</span>
              </div>
            </CardHeader>
            <CardContent>
              <div className="flex gap-2 overflow-x-auto pb-2">
                {columns.map((col) => (
                  <div key={col.tactic} className="w-[180px] shrink-0">
                    <div className="mb-2 rounded-md bg-primary/15 px-2 py-1.5 text-center">
                      <p className="truncate text-xs font-semibold" title={col.tactic}>{col.tactic}</p>
                      <p className="text-[10px] text-muted-foreground">{TACTIC_ES[col.tactic] ?? ''} · {col.count.toLocaleString('es-CO')}</p>
                    </div>
                    <div className="space-y-1.5">
                      {col.techniques.map((t) => (
                        <Cell key={`${col.tactic}-${t.id}`} t={t} intensity={heat(t.count)} />
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </>
      )}
    </>
  );
}

function Cell({ t, intensity }: { t: MitreTechnique; intensity: number }) {
  const bg = `rgba(220,38,38,${(0.55 + intensity * 0.4).toFixed(2)})`;
  return (
    <a
      href={`https://attack.mitre.org/techniques/${t.id.replace('.', '/')}/`}
      target="_blank"
      rel="noreferrer"
      title={`${t.id} · ${t.name} — ${t.count.toLocaleString('es-CO')} eventos · nivel ${t.maxLevel}`}
      className="block rounded border-l-2 px-2 py-1.5 transition-transform hover:scale-[1.02]"
      style={{ background: bg, borderColor: sevBorder(t.maxLevel), textShadow: '0 1px 2px rgba(0,0,0,0.55)' }}
    >
      <div className="flex items-center justify-between gap-1">
        <span className="font-mono text-[10px] font-semibold text-white">{t.id}</span>
        <span className="text-[10px] tabular-nums text-white/95">{t.count > 999 ? `${Math.round(t.count / 1000)}k` : t.count}</span>
      </div>
      <p className="truncate text-[10px] leading-tight text-white/95">{t.name}</p>
    </a>
  );
}

/* ------------------------------- Cobertura ------------------------------- */

const DAYS = [30, 90, 180];

function covColor(pct: number, detected: number): string {
  if (detected === 0) return '#dc2626';
  if (pct >= 20) return '#059669';
  if (pct >= 8) return '#ca8a04';
  return '#ea580c';
}

function CoverageView() {
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
    <>
      <div className="flex items-center justify-end gap-2">
        <div className="flex overflow-hidden rounded-md border border-input">
          {DAYS.map((d) => (
            <button key={d} onClick={() => setDays(d)} className={`px-3 py-1.5 text-xs ${days === d ? 'bg-secondary font-semibold text-foreground' : 'text-muted-foreground hover:bg-secondary/50'}`}>{d}d</button>
          ))}
        </div>
        <Button variant="outline" size="sm" onClick={() => void load(days)} disabled={loading}>
          <RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} />
        </Button>
      </div>

      {error && <Card><CardContent className="p-4 text-sm text-amber-700">{error}</CardContent></Card>}

      <div className="grid gap-3 sm:grid-cols-3">
        <Card><CardContent className="p-4"><p className="flex items-center gap-1.5 text-xs text-muted-foreground"><ShieldCheck className="h-3.5 w-3.5" /> Tácticas con cobertura</p><p className="text-2xl font-bold tabular-nums">{data ? `${data.tacticsCovered}/${data.tacticsTotal}` : '—'}</p></CardContent></Card>
        <Card><CardContent className="p-4"><p className="flex items-center gap-1.5 text-xs text-muted-foreground"><EyeOff className="h-3.5 w-3.5" /> Tácticas ciegas</p><p className="text-2xl font-bold tabular-nums text-rose-600">{data?.tacticsBlind ?? '—'}</p></CardContent></Card>
        <Card><CardContent className="p-4"><p className="text-xs text-muted-foreground">Técnicas detectadas</p><p className="text-2xl font-bold tabular-nums">{data?.techniquesDetected ?? '—'}</p></CardContent></Card>
      </div>

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
    </>
  );
}
