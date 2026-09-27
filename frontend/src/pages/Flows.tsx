/**
 * Flujos de red — analítica tipo NetFlow/QFlow sobre los registros de conexión
 * del SonicWall: conversaciones, puertos, apps, tendencia, beaconing (C2) y
 * escaneo entrante.
 */
import { useEffect, useState, useCallback } from 'react';
import { AxiosError } from 'axios';
import { ResponsiveContainer, AreaChart, Area, XAxis, Tooltip } from 'recharts';
import { Waypoints, Loader2, Radio, Radar, Network, ShieldAlert } from 'lucide-react';
import { flowsApi, type FlowsOverview, type Beacon, type ScanSrc } from '@/lib/flows';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

function fmtTs(ts: string, range: string) {
  const d = new Date(ts);
  return range === '7d' ? d.toLocaleDateString('es-CO', { day: '2-digit', month: '2-digit' }) : d.toLocaleTimeString('es-CO', { hour: '2-digit', minute: '2-digit' });
}

export default function Flows() {
  const [range, setRange] = useState('24h');
  const [ov, setOv] = useState<FlowsOverview | null>(null);
  const [beacons, setBeacons] = useState<Beacon[]>([]);
  const [scans, setScans] = useState<ScanSrc[]>([]);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  const load = useCallback(async () => {
    setBusy(true); setMsg(null);
    try {
      const [o, b, s] = await Promise.all([flowsApi.overview(range), flowsApi.beaconing(range), flowsApi.scans(range)]);
      setOv(o); setBeacons(b); setScans(s);
    } catch (e) { setMsg((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo cargar'); }
    finally { setBusy(false); }
  }, [range]);
  useEffect(() => { void load(); }, [load]);

  return (
    <div className="mx-auto max-w-6xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="hw-mono flex items-center gap-2 text-2xl font-bold tracking-tight">
            <Waypoints className="h-6 w-6 text-primary" /> FLUJOS DE RED
          </h1>
          <p className="hw-mono text-[11px] tracking-wide text-muted-foreground">
            NETFLOW/QFLOW // CONVERSACIONES · BEACONING · ESCANEO
          </p>
        </div>
        <div className="flex items-center gap-1">
          {['1h', '24h', '7d'].map((x) => (
            <Button key={x} size="sm" variant={range === x ? 'default' : 'ghost'} className="h-7 px-2 text-[11px]" onClick={() => setRange(x)} disabled={busy}>{x}</Button>
          ))}
        </div>
      </div>

      {msg && <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">{msg}</div>}

      {/* KPIs */}
      <div className="grid gap-3 sm:grid-cols-4">
        {[
          { icon: Network, col: 'primary', v: ov?.flows ?? 0, l: 'Flujos (conexiones)' },
          { icon: Radio, col: 'destructive', v: beacons.length, l: 'Beaconing (posible C2)' },
          { icon: Radar, col: 'warn-orange', v: scans.length, l: 'Escaneo / fan-out' },
          { icon: ShieldAlert, col: 'cyan', v: ov?.topDst.filter((d) => d.ioc).length ?? 0, l: 'Destinos en IOC' },
        ].map((k) => (
          <div key={k.l} className="hud">
            <span className="hw-clip mb-2 flex h-9 w-9 items-center justify-center" style={{ background: `hsl(var(--${k.col}) / .14)`, color: `hsl(var(--${k.col}))` }}><k.icon className="h-[18px] w-[18px]" /></span>
            <div className="text-2xl font-bold">{k.v.toLocaleString('es-CO')}</div>
            <div className="text-[12px] text-muted-foreground">{k.l}</div>
          </div>
        ))}
      </div>

      {/* Tendencia */}
      {ov && ov.timeline.length > 0 && (
        <Card><CardContent className="p-4">
          <p className="mb-2 text-xs font-semibold text-muted-foreground">Tendencia de flujos</p>
          <ResponsiveContainer width="100%" height={130}>
            <AreaChart data={ov.timeline} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
              <defs><linearGradient id="fl" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="hsl(var(--primary))" stopOpacity={0.5} /><stop offset="100%" stopColor="hsl(var(--primary))" stopOpacity={0} /></linearGradient></defs>
              <XAxis dataKey="ts" tickFormatter={(t) => fmtTs(t, range)} fontSize={10} stroke="hsl(var(--muted-foreground))" minTickGap={40} />
              <Tooltip labelFormatter={(t) => fmtTs(String(t), range)} formatter={(v: number) => [v.toLocaleString('es-CO'), 'flujos']} contentStyle={{ background: 'hsl(var(--card))', border: '1px solid hsl(var(--border))', fontSize: 12 }} />
              <Area type="monotone" dataKey="flows" stroke="hsl(var(--primary))" fill="url(#fl)" strokeWidth={1.5} />
            </AreaChart>
          </ResponsiveContainer>
        </CardContent></Card>
      )}

      {/* Beaconing */}
      <Card>
        <CardHeader><CardTitle className="text-muted-foreground">Beaconing — conexiones periódicas a un destino ({beacons.length})</CardTitle></CardHeader>
        <CardContent>
          {beacons.length === 0 ? <p className="py-4 text-center text-sm text-muted-foreground">Sin patrones de beaconing. 👍</p> : (
            <div className="overflow-x-auto"><table className="w-full text-sm"><thead>
              <tr className="border-b border-border/60 text-left text-xs text-muted-foreground"><th className="pb-2 pr-3">Origen</th><th className="pb-2 pr-3">Destino</th><th className="pb-2 pr-3 text-right">Intervalo</th><th className="pb-2 pr-3 text-right">Conexiones</th><th className="pb-2 text-right">Regularidad</th></tr>
            </thead><tbody>
              {beacons.map((b, i) => (
                <tr key={i} className="border-b border-border/30 last:border-0">
                  <td className="py-2 pr-3 font-mono text-[12px]">{b.src}</td>
                  <td className="py-2 pr-3 font-mono text-[12px]"><a href={`https://www.virustotal.com/gui/ip-address/${b.dst}`} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">{b.dst}</a> <span className="text-[11px] text-muted-foreground">{b.pais}</span>{b.ioc && <span className="ml-1 rounded bg-destructive/15 px-1 text-[9px] text-destructive">IOC</span>}</td>
                  <td className="py-2 pr-3 text-right hw-mono">{b.intervaloSeg}s</td>
                  <td className="py-2 pr-3 text-right">{b.flows.toLocaleString('es-CO')}</td>
                  <td className="py-2 text-right"><span className={b.regularidad >= 90 ? 'font-bold text-destructive' : ''}>{b.regularidad}%</span></td>
                </tr>
              ))}
            </tbody></table></div>
          )}
        </CardContent>
      </Card>

      {/* Escaneo */}
      <Card>
        <CardHeader><CardTitle className="text-muted-foreground">Escaneo / fan-out ({scans.length})</CardTitle></CardHeader>
        <CardContent>
          {scans.length === 0 ? <p className="py-4 text-center text-sm text-muted-foreground">Sin escaneos ni barridos.</p> : (
            <div className="overflow-x-auto"><table className="w-full text-sm"><thead>
              <tr className="border-b border-border/60 text-left text-xs text-muted-foreground"><th className="pb-2 pr-3">Nivel</th><th className="pb-2 pr-3">Tipo</th><th className="pb-2 pr-3">Origen</th><th className="pb-2 pr-3 text-right">Destinos</th><th className="pb-2 text-right">Puertos</th></tr>
            </thead><tbody>
              {scans.map((s, i) => (
                <tr key={i} className="border-b border-border/30 last:border-0">
                  <td className="py-2 pr-3"><span className={`hw-mono rounded px-1.5 py-0.5 text-[10px] font-bold ${s.nivel === 'alto' ? 'bg-destructive/15 text-destructive' : 'bg-amber-500/15 text-amber-500'}`}>{s.nivel}</span></td>
                  <td className="py-2 pr-3 text-[12px] text-muted-foreground">{s.tipo}</td>
                  <td className="py-2 pr-3 font-mono text-[12px]"><a href={`https://www.virustotal.com/gui/ip-address/${s.src}`} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">{s.src}</a> <span className="text-[11px] text-muted-foreground">{s.pais}</span></td>
                  <td className="py-2 pr-3 text-right">{s.destinos.toLocaleString('es-CO')}</td>
                  <td className="py-2 text-right">{s.puertos.toLocaleString('es-CO')}</td>
                </tr>
              ))}
            </tbody></table></div>
          )}
        </CardContent>
      </Card>

      {/* Top listas */}
      <div className="grid gap-4 md:grid-cols-2">
        <Card><CardHeader><CardTitle className="text-muted-foreground">Top destinos externos</CardTitle></CardHeader><CardContent>
          <div className="space-y-1">{(ov?.topDst ?? []).slice(0, 10).map((d) => (
            <div key={d.ip} className="flex items-center justify-between text-[12px]">
              <span className="font-mono">{d.ip} <span className="text-muted-foreground">{d.pais}</span>{d.ioc && <span className="ml-1 rounded bg-destructive/15 px-1 text-[9px] text-destructive">IOC</span>}</span>
              <span className="text-muted-foreground">{d.flows.toLocaleString('es-CO')}</span>
            </div>
          ))}</div>
        </CardContent></Card>
        <Card><CardHeader><CardTitle className="text-muted-foreground">Top puertos · aplicaciones</CardTitle></CardHeader><CardContent>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">{(ov?.topPorts ?? []).slice(0, 8).map((p) => (
              <div key={p.port} className="flex items-center justify-between text-[12px]"><span className="hw-mono">:{p.port}</span><span className="text-muted-foreground">{p.flows.toLocaleString('es-CO')}</span></div>
            ))}</div>
            <div className="space-y-1">{(ov?.topApps ?? []).slice(0, 8).map((a) => (
              <div key={a.app} className="flex items-center justify-between text-[12px]"><span className="truncate">{a.app}</span><span className="ml-2 text-muted-foreground">{a.flows.toLocaleString('es-CO')}</span></div>
            ))}</div>
          </div>
        </CardContent></Card>
      </div>

      {busy && <p className="text-center text-xs text-muted-foreground"><Loader2 className="mr-1 inline h-3 w-3 animate-spin" /> actualizando…</p>}
    </div>
  );
}
