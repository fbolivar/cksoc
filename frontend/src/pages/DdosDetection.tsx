/**
 * Detección DDoS / Bots — señales volumétricas (fan-in, amplificación, flood) y
 * de bots (scraping, HTTP flood, credential stuffing) sobre los flujos del SonicWall.
 */
import { useCallback, useEffect, useState } from 'react';
import type { AxiosError } from 'axios';
import { Waves, Bot, ShieldX, Loader2, RefreshCw, ShieldAlert, MapPin, CheckCircle2, AlertTriangle } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/lib/auth';
import { ddosApi, SEV, type DdosReport, type DdosSignal, type BotSignal } from '@/lib/ddos';

const RANGES = ['1h', '24h', '7d'];

function Sev({ s }: { s: string }) {
  return <span className="rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase text-white" style={{ backgroundColor: SEV[s] }}>{s}</span>;
}

export default function DdosDetection() {
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';
  const [range, setRange] = useState('24h');
  const [data, setData] = useState<DdosReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  const load = useCallback(async (r: string) => {
    setLoading(true); setError(null); setMsg(null);
    try { setData(await ddosApi.get(r)); }
    catch (e) { setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo cargar la detección'); setData(null); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { void load(range); }, [range, load]);

  async function block(ip: string, motivo: string) {
    if (!isAdmin) return;
    if (!confirm(`¿Bloquear ${ip} en el SonicWall?`)) return;
    setBusy(ip); setMsg(null);
    try {
      const { responseApi } = await import('@/lib/response');
      await responseApi.block(ip, motivo);
      setMsg(`IP ${ip} enviada a bloqueo en el firewall.`);
    } catch (e) { setMsg((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo bloquear.'); }
    finally { setBusy(null); }
  }

  const r = data;
  return (
    <div className="mx-auto max-w-6xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 hw-mono text-2xl font-bold tracking-tight"><Waves className="h-6 w-6 text-neon" /> Detección DDoS / Bots</h1>
          <p className="text-sm text-muted-foreground">Volumétrico (fan-in, amplificación, flood) y bots (scraping, HTTP flood, credential stuffing) sobre los flujos del SonicWall.</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex overflow-hidden rounded-md border border-border/60">
            {RANGES.map((x) => (
              <button key={x} onClick={() => setRange(x)} className={`px-3 py-1.5 text-xs ${range === x ? 'bg-primary text-primary-foreground' : 'hover:bg-secondary/60'}`}>{x}</button>
            ))}
          </div>
          <Button variant="outline" size="sm" onClick={() => void load(range)} disabled={loading}><RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} /></Button>
        </div>
      </div>

      {error && <Card><CardContent className="p-4 text-sm text-amber-700">{error}</CardContent></Card>}
      {msg && <div className="flex items-center gap-2 rounded-md border border-primary/30 bg-primary/10 px-3 py-2 text-xs text-primary"><CheckCircle2 className="h-4 w-4" /> {msg}</div>}

      {/* KPIs */}
      {r && (
        <div className="grid grid-cols-3 gap-3">
          <Card><CardContent className="p-3"><div className="text-xs text-muted-foreground">Flujos analizados</div><div className="hw-mono text-xl font-bold">{r.resumen.flujos.toLocaleString('es-CO')}</div></CardContent></Card>
          <Card><CardContent className="p-3"><div className="text-xs text-muted-foreground">Señales volumétricas</div><div className="hw-mono text-xl font-bold" style={{ color: r.resumen.volumetricos ? SEV.alta : SEV.baja }}>{r.resumen.volumetricos}</div></CardContent></Card>
          <Card><CardContent className="p-3"><div className="text-xs text-muted-foreground">Bots detectados</div><div className="hw-mono text-xl font-bold" style={{ color: r.resumen.bots ? SEV.media : SEV.baja }}>{r.resumen.bots}</div></CardContent></Card>
        </div>
      )}

      {loading && !r && <p className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Analizando flujos…</p>}

      {/* Volumétrico */}
      {r && (
        <Card>
          <CardContent className="p-0">
            <div className="border-b border-border/60 px-4 py-2.5 text-sm font-semibold flex items-center gap-2"><ShieldAlert className="h-4 w-4 text-neon" /> Volumétrico / DDoS · {range}</div>
            {r.volumetric.length === 0 ? (
              <p className="flex items-center justify-center gap-2 py-8 text-sm text-muted-foreground"><CheckCircle2 className="h-4 w-4 text-emerald-500" /> Sin señales de saturación en el rango.</p>
            ) : (
              <ul className="divide-y divide-border/30">
                {r.volumetric.map((v: DdosSignal, i) => (
                  <li key={i} className="px-4 py-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <Sev s={v.severidad} />
                      <span className="rounded border border-border/60 px-1.5 py-0.5 text-[10px] uppercase text-muted-foreground">{v.tipo}</span>
                      <span className="font-mono text-xs">→ {v.target}</span>
                      <span className="text-xs text-muted-foreground">{v.sources} orígenes · {v.flows.toLocaleString('es-CO')} flujos{v.topPort ? ` · puerto ${v.topPort}` : ''}{v.iocsTop ? ` · ${v.iocsTop} IOC` : ''}</span>
                    </div>
                    <p className="mt-1 text-xs">{v.descripcion}</p>
                    <div className="mt-1.5 flex flex-wrap gap-1.5">
                      {v.topSources.filter((s) => s.publica).slice(0, 8).map((s) => (
                        <span key={s.ip} className="inline-flex items-center gap-1 rounded border border-border/50 bg-background/40 px-1.5 py-0.5 text-[11px]">
                          {s.ioc && <AlertTriangle className="h-3 w-3 text-red-500" />}
                          <span className="font-mono">{s.ip}</span>
                          {s.pais && <span className="text-muted-foreground"><MapPin className="inline h-3 w-3" />{s.pais}</span>}
                          <span className="text-muted-foreground">×{s.flows}</span>
                          {isAdmin && <button onClick={() => void block(s.ip, `DDoS fan-in contra ${v.target}`)} disabled={busy === s.ip} className="ml-1 text-destructive hover:underline">{busy === s.ip ? '…' : 'bloquear'}</button>}
                        </span>
                      ))}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      )}

      {/* Bots */}
      {r && (
        <Card>
          <CardContent className="p-0">
            <div className="border-b border-border/60 px-4 py-2.5 text-sm font-semibold flex items-center gap-2"><Bot className="h-4 w-4 text-neon" /> Bots / scraping / credential stuffing · {range}</div>
            {r.bots.length === 0 ? (
              <p className="flex items-center justify-center gap-2 py-8 text-sm text-muted-foreground"><CheckCircle2 className="h-4 w-4 text-emerald-500" /> Sin bots externos de alto volumen en el rango.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border/60 text-left text-xs text-muted-foreground">
                      <th className="px-4 py-2 font-medium">Origen</th>
                      <th className="px-2 py-2 font-medium">Tipo</th>
                      <th className="px-2 py-2 font-medium">Destino</th>
                      <th className="px-2 py-2 font-medium text-right">Flujos</th>
                      <th className="px-2 py-2 font-medium">Detalle</th>
                      {isAdmin && <th className="px-2 py-2 font-medium text-right">Acción</th>}
                    </tr>
                  </thead>
                  <tbody>
                    {r.bots.map((b: BotSignal, i) => (
                      <tr key={i} className="border-b border-border/30 last:border-0 hover:bg-secondary/40">
                        <td className="whitespace-nowrap px-4 py-2 font-mono text-xs">
                          {b.ioc && <AlertTriangle className="mr-1 inline h-3 w-3 text-red-500" />}{b.source}
                          {b.pais && <span className="ml-1 text-[10px] text-muted-foreground">{b.pais}</span>}
                        </td>
                        <td className="px-2 py-2"><span className="inline-flex items-center gap-1"><Sev s={b.severidad} /> <span className="text-xs">{b.tipo}</span></span></td>
                        <td className="whitespace-nowrap px-2 py-2 font-mono text-xs">{b.target}{b.topPort ? `:${b.topPort}` : ''}</td>
                        <td className="px-2 py-2 text-right font-semibold tabular-nums">{b.flows.toLocaleString('es-CO')}</td>
                        <td className="max-w-md px-2 py-2"><span className="block truncate text-xs text-muted-foreground">{b.descripcion}</span></td>
                        {isAdmin && (
                          <td className="px-2 py-2 text-right">
                            <Button size="sm" variant="destructive" disabled={busy === b.source} onClick={() => void block(b.source, `Bot/${b.tipo} contra ${b.target}`)}>
                              {busy === b.source ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldX className="h-4 w-4" />} Bloquear
                            </Button>
                          </td>
                        )}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {r && <p className="hw-mono text-[10px] text-muted-foreground">Datos en vivo del SonicWall · nota: para DDoS distribuido real, complementar con la protección de flood/geo-fence del propio firewall.</p>}
    </div>
  );
}
