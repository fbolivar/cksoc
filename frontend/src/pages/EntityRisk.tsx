/**
 * Risk-Based Alerting — priorización de triage por ENTIDAD (host / usuario).
 * En vez de mirar alertas sueltas, muestra a quién atender primero y por qué,
 * con un puntaje acumulado (0-100) y las señales que lo componen.
 */
import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { AxiosError } from 'axios';
import { Target, RefreshCw, Loader2, Server, User, ChevronRight } from 'lucide-react';
import { entityRiskApi, BAND_VAR, BAND_LABEL, type EntityRisk, type EntityRiskReport } from '@/lib/entityRisk';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { RangeTabs, RANGE_24_7_30 } from '@/components/shared/RangeTabs';

type Range = '24h' | '7d' | '30d';
type Tab = 'host' | 'user';

function EntityCard({ e, onClick }: { e: EntityRisk; onClick: () => void }) {
  const v = BAND_VAR[e.band];
  return (
    <button onClick={onClick} title={`Ver detalle de ${e.entity}`}
      className="hw-clip group flex w-full items-center gap-3 border border-border bg-secondary/20 p-3 text-left transition-colors hover:border-primary/50">
      {/* score */}
      <div className="flex w-14 shrink-0 flex-col items-center">
        <span className="hw-tabular text-2xl font-bold leading-none" style={{ color: `hsl(var(--${v}))` }}>{e.score}</span>
        <span className="hw-mono mt-0.5 text-[9px] uppercase tracking-wide" style={{ color: `hsl(var(--${v}))` }}>{BAND_LABEL[e.band]}</span>
      </div>
      {/* cuerpo */}
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          {e.type === 'host' ? <Server className="h-3.5 w-3.5 shrink-0 text-muted-foreground" /> : <User className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />}
          <span className="truncate text-sm font-semibold">{e.entity}</span>
        </div>
        {/* barra */}
        <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-secondary">
          <div className="h-full rounded-full" style={{ width: `${e.score}%`, background: `hsl(var(--${v}))` }} />
        </div>
        {/* contribuciones (por qué) */}
        <div className="mt-1.5 flex flex-wrap gap-1">
          {e.contributions.slice(0, 4).map((c, i) => (
            <span key={i} className="hw-mono inline-flex items-center gap-1 rounded bg-secondary/60 px-1.5 py-0.5 text-[9.5px] text-muted-foreground">
              {c.label} <b className="text-foreground/80">+{c.points}</b>
            </span>
          ))}
        </div>
      </div>
      <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground/40 transition-transform group-hover:translate-x-0.5" />
    </button>
  );
}

export default function EntityRisk() {
  const [range, setRange] = useState<Range>('7d');
  const [tab, setTab] = useState<Tab>('host');
  const [data, setData] = useState<EntityRiskReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  async function load(r: Range) {
    setLoading(true); setError(null);
    try { setData(await entityRiskApi.get(r)); }
    catch (e) { setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo calcular el riesgo por entidad'); }
    finally { setLoading(false); }
  }
  useEffect(() => { load(range); }, [range]);

  const list = useMemo(() => (tab === 'host' ? data?.hosts : data?.users) ?? [], [tab, data]);
  const drill = (e: EntityRisk) => {
    if (e.type === 'host') navigate(`/alertas?agent=${encodeURIComponent(e.entity)}`);
    else navigate(`/comportamiento?user=${encodeURIComponent(e.entity)}`);
  };

  return (
    <div className="mx-auto max-w-5xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 hw-mono text-2xl font-bold tracking-tight">
            <Target className="h-6 w-6 text-neon" /> Riesgo por entidad
          </h1>
          <p className="text-sm text-muted-foreground">Priorización de triage: a quién atender primero y por qué (riesgo acumulado)</p>
        </div>
        <div className="flex items-center gap-2">
          <RangeTabs value={range} onChange={setRange} options={RANGE_24_7_30} />
          <Button variant="outline" size="sm" onClick={() => load(range)} disabled={loading}>
            <RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} /> Actualizar
          </Button>
        </div>
      </div>

      {error && <Card><CardContent className="p-4 text-sm text-amber-700">{error}</CardContent></Card>}

      {/* pestañas host/usuario */}
      <div className="flex gap-0.5 bg-secondary/60 p-0.5 w-fit rounded-md">
        {([['host', 'Hosts', data?.hosts.length], ['user', 'Usuarios', data?.users.length]] as [Tab, string, number | undefined][]).map(([t, label, n]) => (
          <button key={t} onClick={() => setTab(t)}
            className={`hw-tab ${tab === t ? 'on' : ''}`}>{label}{typeof n === 'number' ? ` (${n})` : ''}</button>
        ))}
      </div>

      {loading && !data ? (
        <p className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Calculando riesgo por entidad…</p>
      ) : list.length === 0 ? (
        <Card><CardContent className="py-10 text-center text-sm text-muted-foreground">Sin entidades con riesgo en el rango.</CardContent></Card>
      ) : (
        <div className="space-y-2">
          {list.map((e) => <EntityCard key={`${e.type}-${e.entity}`} e={e} onClick={() => drill(e)} />)}
        </div>
      )}

      {data && (
        <p className="text-center text-[11px] text-muted-foreground/60">
          Riesgo acumulado por señales ponderadas (alertas, vulnerabilidades, autenticación, anomalías UEBA). Actualizado {new Date(data.generatedAt).toLocaleTimeString('es-CO')}.
        </p>
      )}
    </div>
  );
}
