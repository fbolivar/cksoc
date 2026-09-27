/**
 * UEBA · Timeline (estilo Exabeam Smart Timelines): historia cronológica de un
 * usuario con puntuación de anomalía por evento (ubicación atípica, fuera de
 * horario, MFA rechazada, IP/país nuevo, fallos…). Reutiliza el motor de XDR.
 */
import { useState } from 'react';
import { AxiosError } from 'axios';
import { History, Search, Loader2, ShieldAlert, MapPin, KeyRound, XCircle } from 'lucide-react';
import { xdrApi, type UserTimeline, type TlEvent } from '@/lib/xdr';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

const BAND_COLOR: Record<TlEvent['band'], string> = { critico: 'destructive', alto: 'warn-orange', medio: 'primary', bajo: 'muted-foreground' };
const SRC_COLOR: Record<string, string> = { M365: 'hsl(210 90% 62%)', Endpoint: 'hsl(28 90% 58%)', Red: 'hsl(190 80% 55%)', Sistema: 'hsl(265 70% 66%)' };
function fmt(ts: string) { return ts ? new Date(ts).toLocaleString('es-CO') : ''; }

export default function UebaTimeline() {
  const [user, setUser] = useState('');
  const [range, setRange] = useState('7d');
  const [tl, setTl] = useState<UserTimeline | null>(null);
  const [soloAnom, setSoloAnom] = useState(false);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  async function load(u = user) {
    if (!u.trim()) return;
    setBusy(true); setMsg(null);
    try { setTl(await xdrApi.timeline(u.trim(), range)); }
    catch (e) { setMsg((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo cargar el timeline'); }
    finally { setBusy(false); }
  }

  const r = tl?.resumen;
  const eventos = (tl?.events ?? []).filter((e) => !soloAnom || e.anomalias.length);

  return (
    <div className="mx-auto max-w-4xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="hw-mono flex items-center gap-2 text-2xl font-bold tracking-tight">
            <History className="h-6 w-6 text-primary" /> UEBA · TIMELINE
          </h1>
          <p className="hw-mono text-[11px] tracking-wide text-muted-foreground">
            HISTORIA DEL USUARIO // ANOMALÍAS PUNTUADAS // ESTILO SMART TIMELINE
          </p>
        </div>
        <div className="flex items-center gap-1">
          {['24h', '7d', '30d'].map((x) => (
            <Button key={x} size="sm" variant={range === x ? 'default' : 'ghost'} className="h-7 px-2 text-[11px]" onClick={() => setRange(x)}>{x}</Button>
          ))}
        </div>
      </div>

      {msg && <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">{msg}</div>}

      <Card>
        <CardContent className="flex flex-wrap items-end gap-2 p-4">
          <div className="flex-1 space-y-1" style={{ minWidth: 240 }}>
            <label className="text-[11px] text-muted-foreground">Usuario (UPN de M365, o cuenta Windows)</label>
            <Input placeholder="ej. amartinez@col-law.com" value={user}
              onChange={(e) => setUser(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && load()} />
          </div>
          <Button onClick={() => load()} disabled={busy || !user.trim()}>
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />} Ver timeline
          </Button>
        </CardContent>
      </Card>

      {tl && (
        <>
          {/* Resumen */}
          <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-6">
            {[
              { v: r?.total ?? 0, l: 'Eventos' },
              { v: r?.anomalias ?? 0, l: 'Anomalías', hot: true },
              { v: r?.ips ?? 0, l: 'IPs' },
              { v: r?.paises ?? 0, l: 'Países' },
              { v: r?.fallos ?? 0, l: 'Fallos' },
              { v: r?.riesgoMax ?? 0, l: 'Riesgo máx' },
            ].map((k) => (
              <div key={k.l} className="hud">
                <div className={`text-2xl font-bold ${k.hot && (r?.anomalias ?? 0) > 0 ? 'text-destructive' : ''}`}>{k.v.toLocaleString('es-CO')}</div>
                <div className="text-[11px] text-muted-foreground">{k.l}</div>
              </div>
            ))}
          </div>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0">
              <CardTitle className="text-muted-foreground">Línea de tiempo · <span className="hw-mono text-foreground">{tl.user}</span> ({eventos.length})</CardTitle>
              <Button size="sm" variant={soloAnom ? 'default' : 'ghost'} className="h-7 text-[11px]" onClick={() => setSoloAnom((v) => !v)}>
                <ShieldAlert className="mr-1 h-3.5 w-3.5" /> Solo anomalías
              </Button>
            </CardHeader>
            <CardContent>
              {eventos.length === 0 ? (
                <p className="py-6 text-center text-sm text-muted-foreground">Sin eventos para ese usuario/ventana.</p>
              ) : (
                <div className="relative space-y-0 border-l border-border/50 pl-4">
                  {eventos.map((e, i) => {
                    const col = BAND_COLOR[e.band];
                    return (
                      <div key={i} className="relative pb-3">
                        <span className="absolute -left-[21px] top-1 h-2.5 w-2.5 rounded-full" style={{ background: `hsl(var(--${col}))` }} />
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="hw-mono text-[11px] text-muted-foreground">{fmt(e.ts)}</span>
                          <span className="rounded px-1.5 py-0.5 text-[10px] font-semibold" style={{ background: `${SRC_COLOR[e.source] ?? 'hsl(var(--muted-foreground))'}22`, color: SRC_COLOR[e.source] ?? 'hsl(var(--muted-foreground))' }}>{e.source}</span>
                          <span className="text-sm">{e.action}</span>
                          {e.outcome === 'fallo' && <XCircle className="h-3.5 w-3.5 text-destructive" />}
                          {e.risk > 0 && <span className="hw-mono rounded px-1 py-0.5 text-[10px] font-bold" style={{ background: `hsl(var(--${col}) / .16)`, color: `hsl(var(--${col}))` }}>r{e.risk}</span>}
                        </div>
                        <div className="mt-0.5 flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
                          {e.ip && <span className="hw-mono">{e.ip}</span>}
                          {e.pais && <span className="flex items-center gap-0.5"><MapPin className="h-3 w-3" />{[e.ciudad, e.pais].filter(Boolean).join(', ')}</span>}
                          {e.anomalias.map((a) => (
                            <span key={a} className="rounded bg-destructive/12 px-1.5 py-0.5 text-[10px] text-destructive">{a}</span>
                          ))}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
              <p className="mt-3 flex items-start gap-1.5 text-[11px] text-muted-foreground">
                <KeyRound className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                Cada evento se puntúa por señales de anomalía (ubicación atípica fuera de la VPN corporativa, fuera de
                horario, MFA rechazada, IP/país nuevo para el usuario, fallos, nivel de alerta). Reconstruye la "historia"
                del usuario para investigar rápido — como las Smart Timelines de Exabeam.
              </p>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
