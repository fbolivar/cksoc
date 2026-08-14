/**
 * MITRE ATT&CK: matriz tipo Navigator (tacticas en columnas, tecnicas como celdas
 * con heatmap por actividad e indicador de severidad) + tecnicas de mayor riesgo.
 */
import { useEffect, useMemo, useState } from 'react';
import { AxiosError } from 'axios';
import { Crosshair, RefreshCw, Loader2, AlertTriangle } from 'lucide-react';
import { mitreApi, TACTIC_ORDER, TACTIC_ES, type MitreData, type MitreTechnique } from '@/lib/mitre';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { RangeTabs, RANGE_24_7_30 } from '@/components/shared/RangeTabs';
import { KpiCard } from '@/components/shared/KpiCard';

type Range = '24h' | '7d' | '30d';
const HOURS: Record<Range, number> = { '24h': 24, '7d': 168, '30d': 720 };

/** Color de borde por severidad (nivel maximo de la tecnica). */
function sevBorder(level: number): string {
  if (level >= 12) return '#ef4444';
  if (level >= 8) return '#f97316';
  if (level >= 5) return '#eab308';
  return 'transparent';
}

export default function Mitre() {
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

  // Tacticas presentes en orden canonico, con sus tecnicas (una tecnica puede
  // aparecer en varias tacticas).
  const columns = useMemo(() => {
    if (!data) return [];
    const countByTactic = new Map(data.tactics.map((t) => [t.tactic, t.count]));
    const present = TACTIC_ORDER.filter((t) => countByTactic.has(t));
    // tacticas fuera del orden canonico (por si acaso)
    for (const t of data.tactics) if (!present.includes(t.tactic)) present.push(t.tactic);
    return present.map((tactic) => ({
      tactic,
      count: countByTactic.get(tactic) ?? 0,
      techniques: data.techniques
        .filter((te) => te.tactics.includes(tactic))
        .sort((a, b) => b.count - a.count),
    }));
  }, [data]);

  const maxCount = useMemo(() => Math.max(1, ...(data?.techniques ?? []).map((t) => t.count)), [data]);
  const riesgo = useMemo(
    () => [...(data?.techniques ?? [])].sort((a, b) => b.maxLevel - a.maxLevel || b.count - a.count).slice(0, 8),
    [data]
  );

  // Intensidad logaritmica (T1046 domina), 0..1
  const heat = (count: number) => Math.log(count + 1) / Math.log(maxCount + 1);

  return (
    <div className="mx-auto max-w-[1400px] space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 hw-mono text-2xl font-bold tracking-tight">
            <Crosshair className="h-6 w-6 text-neon" /> MITRE ATT&CK
          </h1>
          <p className="text-sm text-muted-foreground">
            Tácticas y técnicas adversarias detectadas, mapeadas al framework MITRE ATT&CK
          </p>
        </div>
        <div className="flex items-center gap-2">
          <RangeTabs value={range} onChange={setRange} options={RANGE_24_7_30} />
          <Button variant="outline" size="sm" onClick={() => load(range)} disabled={loading}>
            <RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} /> Actualizar
          </Button>
        </div>
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

          {/* Tecnicas de mayor riesgo */}
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

          {/* Matriz ATT&CK */}
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
    </div>
  );
}

function Cell({ t, intensity }: { t: MitreTechnique; intensity: number }) {
  // Opacidad minima alta para que las celdas poco activas sigan legibles.
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
