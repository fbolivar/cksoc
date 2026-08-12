/**
 * Threat Hunting: búsqueda ad-hoc sobre las alertas de Wazuh con filtros por
 * campo, texto y tiempo, más paneles de agregación (top reglas / agentes / IPs
 * / MITRE) clicables para refinar la caza.
 */
import { useEffect, useState, useCallback } from 'react';
import { Crosshair, Search, X, Loader2, Filter, Bookmark, Bell, BellOff, Play, Trash2 } from 'lucide-react';
import { huntApi, type HuntResult, type HuntQuery, type Bucket } from '@/lib/hunt';
import { savedHuntsApi, type SavedHunt } from '@/lib/savedHunts';

const RANGES = [
  { v: '1h', l: '1h' }, { v: '24h', l: '24h' }, { v: '7d', l: '7d' }, { v: '30d', l: '30d' },
];

function bandColor(level: number): string {
  if (level >= 12) return 'text-destructive';
  if (level >= 8) return 'text-warn';
  if (level >= 5) return 'text-yellow-400';
  return 'text-muted-foreground';
}

function AggPanel({ title, buckets, onPick }: { title: string; buckets: Bucket[]; onPick: (key: string) => void }) {
  const max = Math.max(1, ...buckets.map((b) => b.count));
  return (
    <div className="glass rounded-lg p-3">
      <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">{title}</p>
      {buckets.length === 0 ? (
        <p className="text-xs text-muted-foreground/60">—</p>
      ) : (
        <div className="space-y-1">
          {buckets.slice(0, 8).map((b) => (
            <button
              key={b.key}
              onClick={() => onPick(b.key)}
              className="group relative flex w-full items-center justify-between gap-2 overflow-hidden rounded px-2 py-1 text-left text-xs hover:bg-secondary"
              title={b.label || b.key}
            >
              <span className="absolute inset-y-0 left-0 bg-primary/10" style={{ width: `${(b.count / max) * 100}%` }} />
              <span className="relative z-10 truncate">{b.label ? `${b.key} · ${b.label}` : b.key}</span>
              <span className="relative z-10 shrink-0 tabular-nums text-muted-foreground">{b.count}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export default function Hunt() {
  const [range, setRange] = useState('24h');
  const [q, setQ] = useState('');
  const [minLevel, setMinLevel] = useState<number>(0);
  const [filters, setFilters] = useState<{ agent?: string; ruleId?: string; srcip?: string; mitre?: string }>({});
  const [res, setRes] = useState<HuntResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [saved, setSaved] = useState<SavedHunt[]>([]);

  const currentQuery = (): HuntQuery => ({ range, q: q || undefined, minLevel: minLevel || undefined, ...filters });
  const loadSaved = () => savedHuntsApi.list().then(setSaved).catch(() => {});
  useEffect(() => { void loadSaved(); }, []);

  const saveCurrent = async () => {
    const name = prompt('Nombre de la cacería:');
    if (!name) return;
    const alertEnabled = confirm('¿Activar alerta? Se avisará (campanita) cuando el número de coincidencias supere el umbral.');
    await savedHuntsApi.create({ name, query: currentQuery(), alertEnabled, threshold: 1, intervalMin: 15 });
    await loadSaved();
  };
  const applySaved = (h: SavedHunt) => {
    setRange(h.query.range ?? '24h');
    setQ(h.query.q ?? '');
    setMinLevel(h.query.minLevel ?? 0);
    setFilters({ agent: h.query.agent, ruleId: h.query.ruleId, srcip: h.query.srcip, mitre: h.query.mitre });
  };

  const run = useCallback(async () => {
    setLoading(true);
    setErr(null);
    try {
      const query: HuntQuery = { range, q: q || undefined, minLevel: minLevel || undefined, size: 100, ...filters };
      setRes(await huntApi.search(query));
    } catch {
      setErr('No se pudo consultar el índice de alertas (Wazuh Indexer).');
      setRes(null);
    } finally {
      setLoading(false);
    }
  }, [range, q, minLevel, filters]);

  useEffect(() => {
    void run();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [range, minLevel, filters]);

  const activeChips = Object.entries(filters).filter(([, v]) => v);

  return (
    <div className="mx-auto max-w-6xl space-y-4">
      <div>
        <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
          <Crosshair className="h-6 w-6 text-brand" /> Threat Hunting
        </h1>
        <p className="text-sm text-muted-foreground">Caza de amenazas — busca en las alertas por campo, texto y tiempo</p>
      </div>

      {/* Barra de búsqueda + filtros */}
      <div className="glass rounded-lg p-3">
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative min-w-[200px] flex-1">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && void run()}
              placeholder="texto en la descripción de la regla… (Enter para buscar)"
              className="h-9 w-full rounded-md border border-input bg-background pl-8 pr-3 text-sm"
            />
          </div>
          <select value={range} onChange={(e) => setRange(e.target.value)} className="h-9 rounded-md border border-input bg-background px-2 text-sm">
            {RANGES.map((r) => <option key={r.v} value={r.v}>{r.l}</option>)}
          </select>
          <select value={minLevel} onChange={(e) => setMinLevel(Number(e.target.value))} className="h-9 rounded-md border border-input bg-background px-2 text-sm">
            <option value={0}>Cualquier nivel</option>
            <option value={5}>Nivel ≥ 5 (media)</option>
            <option value={8}>Nivel ≥ 8 (alta)</option>
            <option value={12}>Nivel ≥ 12 (crítica)</option>
          </select>
          <button onClick={() => void run()} className="flex h-9 items-center gap-1.5 rounded-md bg-primary px-4 text-sm font-medium text-primary-foreground">
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />} Buscar
          </button>
          <button onClick={() => void saveCurrent()} className="flex h-9 items-center gap-1.5 rounded-md bg-secondary px-3 text-sm text-foreground hover:bg-secondary/70" title="Guardar esta cacería">
            <Bookmark className="h-4 w-4" /> Guardar
          </button>
        </div>

        {saved.length > 0 && (
          <div className="mt-2 flex flex-wrap items-center gap-2 border-t border-border/40 pt-2">
            <span className="text-[11px] text-muted-foreground">Guardadas:</span>
            {saved.map((h) => (
              <span key={h.id} className="flex items-center gap-1 rounded-full border border-border/60 bg-card/40 px-2 py-0.5 text-[11px]">
                <button onClick={() => applySaved(h)} className="hover:text-brand" title="Cargar filtros">{h.name}</button>
                {h.alertEnabled ? <Bell className="h-3 w-3 text-brand" /> : <BellOff className="h-3 w-3 text-muted-foreground/50" />}
                {h.lastCount !== null && <span className="text-muted-foreground">{h.lastCount}</span>}
                <button onClick={async () => { await savedHuntsApi.update(h.id, { alertEnabled: !h.alertEnabled }); void loadSaved(); }} className="text-muted-foreground hover:text-foreground" title="Activar/desactivar alerta">{h.alertEnabled ? <BellOff className="h-3 w-3" /> : <Bell className="h-3 w-3" />}</button>
                <button onClick={async () => { await savedHuntsApi.run(h.id); void loadSaved(); }} className="text-muted-foreground hover:text-foreground" title="Correr ahora"><Play className="h-3 w-3" /></button>
                <button onClick={async () => { if (confirm(`¿Eliminar "${h.name}"?`)) { await savedHuntsApi.remove(h.id); void loadSaved(); } }} className="text-muted-foreground hover:text-destructive" title="Eliminar"><Trash2 className="h-3 w-3" /></button>
              </span>
            ))}
          </div>
        )}

        {activeChips.length > 0 && (
          <div className="mt-2 flex flex-wrap items-center gap-1.5">
            <Filter className="h-3.5 w-3.5 text-muted-foreground" />
            {activeChips.map(([k, v]) => (
              <span key={k} className="flex items-center gap-1 rounded-full bg-brand/15 px-2 py-0.5 text-[11px] text-brand">
                {k}: {v}
                <button onClick={() => setFilters((f) => ({ ...f, [k]: undefined }))}><X className="h-3 w-3" /></button>
              </span>
            ))}
            <button onClick={() => setFilters({})} className="text-[11px] text-muted-foreground hover:text-foreground">limpiar</button>
          </div>
        )}
      </div>

      {err && <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">{err}</div>}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_260px]">
        {/* Resultados */}
        <div className="glass overflow-hidden rounded-lg">
          <div className="border-b border-border/60 px-4 py-2.5 text-sm">
            {res ? (
              <span><span className="font-semibold">{res.total.toLocaleString('es-CO')}</span>{res.capped ? '+' : ''} alertas · mostrando {res.items.length}</span>
            ) : loading ? 'Buscando…' : '—'}
          </div>
          <div className="max-h-[70vh] overflow-auto">
            {loading && !res ? (
              <div className="p-8 text-center text-muted-foreground"><Loader2 className="mx-auto h-5 w-5 animate-spin" /></div>
            ) : res && res.items.length === 0 ? (
              <div className="p-10 text-center text-sm text-muted-foreground">Sin resultados para estos filtros.</div>
            ) : (
              <table className="w-full text-sm">
                <thead className="sticky top-0 bg-card">
                  <tr className="border-b border-border/50 text-left text-xs text-muted-foreground">
                    <th className="px-3 py-2 font-medium">Hora</th>
                    <th className="px-3 py-2 font-medium">Niv</th>
                    <th className="px-3 py-2 font-medium">Regla</th>
                    <th className="px-3 py-2 font-medium">Agente</th>
                    <th className="px-3 py-2 font-medium">IP orig</th>
                    <th className="px-3 py-2 font-medium">MITRE</th>
                  </tr>
                </thead>
                <tbody>
                  {res?.items.map((it) => (
                    <tr key={it.id} className="border-b border-border/30 hover:bg-secondary/40">
                      <td className="whitespace-nowrap px-3 py-1.5 text-[11px] text-muted-foreground">{new Date(it.timestamp).toLocaleString('es-CO', { dateStyle: 'short', timeStyle: 'medium' })}</td>
                      <td className={`px-3 py-1.5 font-semibold ${bandColor(it.level)}`}>{it.level}</td>
                      <td className="px-3 py-1.5">
                        <span className="text-xs">{it.description}</span>
                        <button onClick={() => setFilters((f) => ({ ...f, ruleId: it.ruleId }))} className="ml-1 font-mono text-[10px] text-muted-foreground hover:text-brand">#{it.ruleId}</button>
                      </td>
                      <td className="px-3 py-1.5">
                        <button onClick={() => setFilters((f) => ({ ...f, agent: it.agent }))} className="text-xs hover:text-brand">{it.agent || '—'}</button>
                      </td>
                      <td className="px-3 py-1.5">
                        {it.srcip ? <button onClick={() => setFilters((f) => ({ ...f, srcip: it.srcip! }))} className="font-mono text-[11px] hover:text-brand">{it.srcip}</button> : '—'}
                      </td>
                      <td className="px-3 py-1.5">
                        {it.mitre.map((m) => (
                          <button key={m} onClick={() => setFilters((f) => ({ ...f, mitre: m }))} className="mr-1 rounded bg-secondary px-1 text-[10px] hover:text-brand">{m}</button>
                        ))}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Agregaciones */}
        <div className="space-y-3">
          <AggPanel title="Top reglas" buckets={res?.aggs.rules ?? []} onPick={(k) => setFilters((f) => ({ ...f, ruleId: k }))} />
          <AggPanel title="Top agentes" buckets={res?.aggs.agents ?? []} onPick={(k) => setFilters((f) => ({ ...f, agent: k }))} />
          <AggPanel title="Top IPs origen" buckets={res?.aggs.srcips ?? []} onPick={(k) => setFilters((f) => ({ ...f, srcip: k }))} />
          <AggPanel title="Top MITRE" buckets={res?.aggs.mitre ?? []} onPick={(k) => setFilters((f) => ({ ...f, mitre: k }))} />
        </div>
      </div>
    </div>
  );
}
