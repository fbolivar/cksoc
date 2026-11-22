import { useEffect, useState } from 'react';
import { Biohazard, RefreshCw, ExternalLink, AlertTriangle, Globe2, Scale } from 'lucide-react';
import { ransomwareApi, type RwOverview, type RwVictim, type Relevance } from '@/lib/ransomware';

const RANGES = [
  { d: 7, label: '7 días' }, { d: 30, label: '30 días' }, { d: 90, label: '90 días' },
];

function relBadge(r: Relevance): { cls: string; txt: string } | null {
  if (r === 'directo') return { cls: 'bg-red-500/15 text-red-500 border-red-500/40', txt: 'DIRECTO' };
  if (r === 'pais') return { cls: 'bg-amber-500/15 text-amber-500 border-amber-500/40', txt: 'PAÍS' };
  if (r === 'sector') return { cls: 'bg-orange-500/15 text-orange-400 border-orange-500/40', txt: 'SECTOR' };
  return null;
}

function fmtDate(s: string | null): string {
  if (!s) return '—';
  const t = Date.parse(s);
  return Number.isFinite(t) ? new Date(t).toLocaleDateString('es-CO', { day: '2-digit', month: 'short', year: '2-digit' }) : '—';
}

function Kpi({ label, value, danger }: { label: string; value: number | string; danger?: boolean }) {
  return (
    <div className="glass rounded-lg p-3">
      <div className={`text-2xl font-bold ${danger ? 'text-red-500' : 'text-foreground'}`}>{value}</div>
      <div className="text-[11px] text-muted-foreground">{label}</div>
    </div>
  );
}

function VictimRow({ v, highlight }: { v: RwVictim; highlight?: boolean }) {
  const b = relBadge(v.relevance);
  return (
    <div className={`rounded border-l-2 px-2.5 py-1.5 ${highlight && v.relevance === 'directo' ? 'border-l-red-500 bg-red-500/5' : highlight ? 'border-l-amber-500/60 bg-secondary/30' : 'border-l-border bg-secondary/20'}`}>
      <div className="flex items-center justify-between gap-2">
        <span className="truncate text-xs font-medium">{v.victim}</span>
        <div className="flex shrink-0 items-center gap-1.5">
          {b && <span className={`rounded border px-1.5 py-0.5 text-[9px] font-semibold ${b.cls}`}>{b.txt}</span>}
          <span className="rounded bg-secondary px-1.5 py-0.5 text-[9px] uppercase text-muted-foreground">{v.group}</span>
        </div>
      </div>
      <p className="hw-mono mt-0.5 flex items-center gap-1.5 truncate text-[10px] text-muted-foreground">
        {v.country && <span>{v.country}</span>}
        {v.sector && <span>· {v.sector}</span>}
        <span>· {fmtDate(v.published)}</span>
        {v.url && <a href={v.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-0.5 text-primary hover:underline"><ExternalLink className="h-3 w-3" /> post</a>}
      </p>
    </div>
  );
}

export default function Ransomware() {
  const [days, setDays] = useState(30);
  const [d, setD] = useState<RwOverview | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [refMsg, setRefMsg] = useState<string | null>(null);

  async function load(dd: number) {
    setLoading(true); setErr(null);
    try { setD(await ransomwareApi.overview(dd)); }
    catch { setErr('No se pudo consultar la fuente de ransomware (ransomware.live).'); setD(null); }
    finally { setLoading(false); }
  }
  useEffect(() => { void load(days); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [days]);

  async function onRefresh() {
    setRefreshing(true); setRefMsg(null);
    try { const r = await ransomwareApi.refresh(); setRefMsg(`Chequeo listo: ${r.nuevos} nueva(s) víctima(s) relevante(s).`); await load(days); }
    catch { setRefMsg('No se pudo refrescar.'); }
    finally { setRefreshing(false); }
  }

  const maxGroup = Math.max(1, ...(d?.topGrupos ?? []).map((g) => g.count));

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-bold"><Biohazard className="h-5 w-5 text-red-500" /> Inteligencia de Ransomware</h1>
          <p className="text-sm text-muted-foreground">Grupos de extorsión activos y víctimas publicadas en sus sitios de filtración, resaltando lo relevante para el cliente (marca, país y sector).</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex rounded-lg border border-border bg-secondary/40 p-0.5">
            {RANGES.map((r) => (
              <button key={r.d} onClick={() => setDays(r.d)} className={`rounded-md px-3 py-1 text-xs transition ${days === r.d ? 'bg-brand text-white' : 'text-muted-foreground hover:text-foreground'}`}>{r.label}</button>
            ))}
          </div>
          <button onClick={() => void onRefresh()} disabled={refreshing} className="inline-flex items-center gap-1 rounded-lg border border-border bg-secondary/40 px-3 py-1.5 text-xs hover:bg-secondary disabled:opacity-50">
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? 'animate-spin' : ''}`} /> Buscar nuevas
          </button>
        </div>
      </div>

      {refMsg && <div className="rounded-lg border border-border bg-secondary/30 px-4 py-2 text-xs text-muted-foreground">{refMsg}</div>}
      {err && <div className="flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-2 text-xs text-amber-600"><AlertTriangle className="h-4 w-4" /> {err}</div>}

      {d && (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
            <Kpi label={`Víctimas (${days}d)`} value={d.kpis.recientes} />
            <Kpi label="Grupos activos" value={d.kpis.gruposActivos} />
            <Kpi label={`Víctimas ${d.pais} (histórico)`} value={d.kpis.victimasPais} />
            <Kpi label="En el sector" value={d.kpis.sectorHits} danger={d.kpis.sectorHits > 0} />
            <Kpi label="Coincidencia directa" value={d.kpis.directos} danger={d.kpis.directos > 0} />
          </div>

          <div className="grid gap-4 lg:grid-cols-3">
            <div className="lg:col-span-2">
              <div className="glass rounded-lg p-4">
                <p className="mb-3 flex items-center gap-2 text-sm font-semibold">
                  <AlertTriangle className="h-4 w-4 text-red-500" /> Relevantes para el cliente
                  {!d.watchActivo && <span className="text-[10px] font-normal text-muted-foreground">(sin términos de marca configurados; se filtra por país y sector)</span>}
                </p>
                {d.relevantes.length === 0 ? (
                  <p className="py-6 text-center text-xs text-muted-foreground">Sin víctimas relevantes en el rango. 👍</p>
                ) : (
                  <div className="max-h-[380px] space-y-1.5 overflow-y-auto">
                    {d.relevantes.map((v, i) => <VictimRow key={i} v={v} highlight />)}
                  </div>
                )}
              </div>
            </div>

            <div className="glass rounded-lg p-4">
              <p className="mb-3 text-sm font-semibold">Grupos más activos ({days}d)</p>
              <div className="space-y-1.5">
                {d.topGrupos.map((g) => (
                  <div key={g.group}>
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="truncate font-medium">{g.group}</span>
                      <span className="hw-tabular text-muted-foreground">{g.count}</span>
                    </div>
                    <div className="h-1.5 w-full overflow-hidden rounded-full bg-secondary/60">
                      <div className="h-full bg-red-500/70" style={{ width: `${(g.count / maxGroup) * 100}%` }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="glass rounded-lg p-4">
            <p className="mb-3 flex items-center gap-2 text-sm font-semibold"><Globe2 className="h-4 w-4 text-muted-foreground" /> Víctimas recientes (global)</p>
            <div className="grid max-h-[420px] gap-1.5 overflow-y-auto md:grid-cols-2">
              {d.recientes.map((v, i) => <VictimRow key={i} v={v} />)}
            </div>
          </div>

          <p className="flex items-center justify-center gap-1 text-center text-[11px] text-muted-foreground/60">
            <Scale className="h-3 w-3" /> Fuente: ransomware.live (OSINT de sitios de extorsión). La marca del cliente se filtra localmente, no se envía a la fuente. Actualizado {new Date(d.generatedAt).toLocaleTimeString('es-CO')}.
          </p>
        </>
      )}
      {loading && !d && <div className="glass h-40 animate-pulse rounded-lg" />}
    </div>
  );
}
