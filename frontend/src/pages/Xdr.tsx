/**
 * XDR — grafo de actividad cross-dominio (SmartGrouping). Agrupa alertas por
 * entidades compartidas y permite pivotear un grafo de investigación.
 */
import { useEffect, useState, useCallback } from 'react';
import { AxiosError } from 'axios';
import { Share2, Loader2, Search, ArrowLeft, ShieldAlert } from 'lucide-react';
import { xdrApi, type ActivityGroup, type ActivityGraph, type GraphNode, type EntType } from '@/lib/xdr';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

const TYPE_COLOR: Record<EntType, string> = { ip: 'hsl(190 80% 55%)', host: 'hsl(210 90% 62%)', user: 'hsl(28 90% 58%)', domain: 'hsl(265 70% 66%)' };
const TYPE_LABEL: Record<EntType, string> = { ip: 'IP', host: 'Host', user: 'Usuario', domain: 'Dominio' };
const IOC_COLOR = 'hsl(0 82% 60%)';

function fmt(ts: string) { return ts ? new Date(ts).toLocaleString('es-CO') : ''; }

function Graph({ g, onPivot }: { g: ActivityGraph; onPivot: (t: EntType, v: string) => void }) {
  const W = 820, H = 500, cx = W / 2, cy = H / 2, R = 185;
  const seed = g.nodes.find((n) => n.seed);
  const others = g.nodes.filter((n) => !n.seed).slice(0, 26);
  const pos = new Map<string, { x: number; y: number }>();
  if (seed) pos.set(seed.id, { x: cx, y: cy });
  others.forEach((n, i) => { const a = (i / others.length) * 2 * Math.PI - Math.PI / 2; pos.set(n.id, { x: cx + R * Math.cos(a), y: cy + R * Math.sin(a) }); });
  const shown = [seed, ...others].filter(Boolean) as GraphNode[];
  const rad = (n: GraphNode) => 7 + Math.min(15, Math.sqrt(n.alertas));
  const edges = g.edges.filter((e) => pos.has(e.from) && pos.has(e.to));
  const maxW = Math.max(1, ...edges.map((e) => e.weight));

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ maxHeight: 520 }}>
      {edges.map((e, i) => {
        const a = pos.get(e.from)!, b = pos.get(e.to)!;
        return <line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="hsl(var(--muted-foreground))" strokeOpacity={0.18 + 0.4 * (e.weight / maxW)} strokeWidth={0.5 + 2 * (e.weight / maxW)} />;
      })}
      {shown.map((n) => {
        const p = pos.get(n.id)!; const r = rad(n);
        return (
          <g key={n.id} style={{ cursor: 'pointer' }} onClick={() => onPivot(n.type, n.label)}>
            <circle cx={p.x} cy={p.y} r={r} fill={TYPE_COLOR[n.type]} fillOpacity={n.seed ? 1 : 0.85} stroke={n.ioc ? IOC_COLOR : (n.seed ? '#fff' : 'transparent')} strokeWidth={n.ioc ? 3 : (n.seed ? 2 : 0)} />
            <text x={p.x} y={p.y + r + 11} textAnchor="middle" fontSize={10} fill="hsl(var(--foreground))" className="hw-mono">
              {n.label.length > 22 ? n.label.slice(0, 20) + '…' : n.label}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

export default function Xdr() {
  const [range, setRange] = useState('24h');
  const [groups, setGroups] = useState<ActivityGroup[] | null>(null);
  const [graph, setGraph] = useState<ActivityGraph | null>(null);
  const [seedType, setSeedType] = useState<EntType>('ip');
  const [seedVal, setSeedVal] = useState('');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  const loadGroups = useCallback(async () => {
    try { setGroups(await xdrApi.groups(range)); } catch { setGroups([]); }
  }, [range]);
  useEffect(() => { void loadGroups(); }, [loadGroups]);

  async function pivot(type: EntType, value: string) {
    setBusy(true); setMsg(null); setSeedType(type); setSeedVal(value);
    try { setGraph(await xdrApi.graph(type, value, '30d')); }
    catch (e) { setMsg((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo construir el grafo'); }
    finally { setBusy(false); }
  }

  return (
    <div className="mx-auto max-w-6xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="hw-mono flex items-center gap-2 text-2xl font-bold tracking-tight">
            <Share2 className="h-6 w-6 text-primary" /> XDR · GRAFO DE ACTIVIDAD
          </h1>
          <p className="hw-mono text-[11px] tracking-wide text-muted-foreground">
            SMARTGROUPING // IP · HOST · USUARIO · DOMINIO // UNA HISTORIA
          </p>
        </div>
        <div className="flex items-center gap-1">
          {['24h', '7d', '30d'].map((r) => (
            <Button key={r} size="sm" variant={range === r ? 'default' : 'ghost'} className="h-7 px-2 text-[11px]" onClick={() => setRange(r)}>{r}</Button>
          ))}
        </div>
      </div>

      {msg && <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">{msg}</div>}

      {/* Buscador de entidad */}
      <Card>
        <CardContent className="flex flex-wrap items-end gap-2 p-4">
          <div className="space-y-1">
            <label className="text-[11px] text-muted-foreground">Tipo</label>
            <select value={seedType} onChange={(e) => setSeedType(e.target.value as EntType)} className="h-9 rounded-md border border-border bg-background px-2 text-sm">
              {(['ip', 'host', 'user', 'domain'] as EntType[]).map((t) => <option key={t} value={t}>{TYPE_LABEL[t]}</option>)}
            </select>
          </div>
          <div className="flex-1 space-y-1" style={{ minWidth: 220 }}>
            <label className="text-[11px] text-muted-foreground">Entidad a investigar</label>
            <Input placeholder="ej. 78.110.173.168 / SISTEMAS / user@dominio" value={seedVal}
              onChange={(e) => setSeedVal(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && seedVal.trim() && pivot(seedType, seedVal.trim())} />
          </div>
          <Button onClick={() => seedVal.trim() && pivot(seedType, seedVal.trim())} disabled={busy || !seedVal.trim()}>
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />} Construir grafo
          </Button>
        </CardContent>
      </Card>

      {/* Vista grafo */}
      {graph ? (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0">
            <CardTitle className="text-muted-foreground">
              Grafo · {TYPE_LABEL[graph.seed.type]} <span className="hw-mono text-foreground">{graph.seed.value}</span>
              <span className="ml-2 text-[11px] font-normal">({graph.nodes.length} entidades · {graph.stats.alertas.toLocaleString('es-CO')} alertas)</span>
            </CardTitle>
            <Button size="sm" variant="ghost" onClick={() => setGraph(null)}><ArrowLeft className="h-4 w-4" /> Grupos</Button>
          </CardHeader>
          <CardContent>
            <div className="mb-2 flex flex-wrap gap-3 text-[11px] text-muted-foreground">
              {(['ip', 'host', 'user', 'domain'] as EntType[]).map((t) => (
                <span key={t} className="flex items-center gap-1"><span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: TYPE_COLOR[t] }} /> {TYPE_LABEL[t]}</span>
              ))}
              <span className="flex items-center gap-1"><span className="inline-block h-2.5 w-2.5 rounded-full border-2" style={{ borderColor: IOC_COLOR }} /> IOC</span>
              <span className="italic">clic en un nodo para pivotear</span>
            </div>
            <Graph g={graph} onPivot={pivot} />
            {/* Línea de tiempo */}
            <div className="mt-3">
              <p className="mb-1 text-xs font-semibold text-muted-foreground">Línea de tiempo ({graph.timeline.length})</p>
              <div className="max-h-64 overflow-y-auto rounded-md border border-border/50">
                <table className="w-full text-[12px]">
                  <tbody>
                    {graph.timeline.slice(0, 40).map((t, i) => (
                      <tr key={i} className="border-b border-border/30 last:border-0">
                        <td className="whitespace-nowrap px-2 py-1.5 text-muted-foreground">{fmt(t.ts)}</td>
                        <td className="px-2 py-1.5"><span className={t.level >= 12 ? 'font-bold text-destructive' : t.level >= 8 ? 'text-amber-500' : ''}>[{t.level}]</span> {t.rule}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </CardContent>
        </Card>
      ) : (
        /* Vista grupos de actividad */
        <Card>
          <CardHeader><CardTitle className="text-muted-foreground">Grupos de actividad {groups ? `(${groups.length})` : ''}</CardTitle></CardHeader>
          <CardContent className="space-y-3">
            {!groups ? (
              <p className="py-6 text-center text-sm text-muted-foreground"><Loader2 className="mr-2 inline h-4 w-4 animate-spin" /> Analizando…</p>
            ) : groups.length === 0 ? (
              <p className="py-6 text-center text-sm text-muted-foreground">Sin grupos de actividad notables en esta ventana. 👍</p>
            ) : groups.map((g) => (
              <div key={g.id} className="rounded-md border border-border/50 bg-card/40 p-3">
                <div className="mb-1.5 flex flex-wrap items-center gap-2">
                  <span className={`hw-mono rounded px-1.5 py-0.5 text-[10px] font-bold ${g.maxLevel >= 12 ? 'bg-destructive/15 text-destructive' : 'bg-amber-500/15 text-amber-500'}`}>nivel {g.maxLevel}</span>
                  <span className="text-sm font-semibold">{g.alertas.toLocaleString('es-CO')} alertas · {g.reglas} reglas</span>
                  <span className="text-[11px] text-muted-foreground">{fmt(g.desde)} → {fmt(g.hasta)}</span>
                  <span className="ml-auto text-[11px] text-muted-foreground">{g.tipos.map((t) => TYPE_LABEL[t]).join(' · ')}</span>
                </div>
                <div className="mb-1.5 flex flex-wrap gap-1">
                  {g.entidades.map((e) => (
                    <button key={e.type + e.label} onClick={() => pivot(e.type, e.label)}
                      className="rounded px-1.5 py-0.5 text-[11px] hover:underline"
                      style={{ background: `${TYPE_COLOR[e.type]}22`, color: TYPE_COLOR[e.type], border: e.ioc ? `1px solid ${IOC_COLOR}` : '1px solid transparent' }}
                      title={e.ioc ? 'IOC conocido · clic para el grafo' : 'clic para el grafo'}>
                      {e.ioc && <ShieldAlert className="mr-0.5 inline h-3 w-3" />}{e.label}
                    </button>
                  ))}
                </div>
                <p className="text-[11px] text-muted-foreground">{g.topReglas.map((r) => `${r.desc} (${r.count})`).join(' · ')}</p>
              </div>
            ))}
            <p className="text-[11px] text-muted-foreground">
              Cada grupo une alertas que comparten entidades (misma IP/host/usuario/dominio) en una sola historia. Clic en
              cualquier entidad para abrir su <b>grafo de actividad</b> y pivotear la investigación.
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
