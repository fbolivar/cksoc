/**
 * NDR · Visibilidad de red. Construido sobre la telemetría del FortiGate
 * (Application Control / IPS) que llega a Wazuh: top talkers, dominios (SNI),
 * aplicaciones, cruce con IOCs y alertas IPS.
 */
import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { AxiosError } from 'axios';
import { Network, RefreshCw, Loader2, ShieldAlert, Globe2, Upload } from 'lucide-react';
import { ndrApi, type NdrOverview } from '@/lib/ndr';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

type Range = '1h' | '24h' | '7d';
const RANGES: Range[] = ['1h', '24h', '7d'];
const fmt = (n: number) => n.toLocaleString('es-CO');
const fmtBytes = (n: number) => n >= 1e9 ? `${(n / 1e9).toFixed(2)} GB` : n >= 1e6 ? `${(n / 1e6).toFixed(1)} MB` : `${(n / 1e3).toFixed(0)} KB`;
const VERDICT_VAR: Record<string, string> = { malicioso: 'destructive', sospechoso: 'warn-orange', limpio: 'success', interno: 'cyan', desconocido: 'muted-foreground' };

function Kpi({ label, value, danger }: { label: string; value: string; danger?: boolean }) {
  return (
    <Card><CardContent className="p-4">
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className="text-2xl font-bold tabular-nums" style={danger ? { color: 'hsl(var(--destructive))' } : undefined}>{value}</p>
    </CardContent></Card>
  );
}

function BarRow({ label, count, max, onClick, mono }: { label: string; count: number; max: number; onClick?: () => void; mono?: boolean }) {
  return (
    <div className={`flex items-center gap-2 ${onClick ? 'cursor-pointer' : ''}`} onClick={onClick} title={onClick ? `Ver alertas de ${label}` : undefined}>
      <div className="min-w-0 flex-1">
        <div className="flex items-center justify-between gap-2">
          <span className={`truncate text-xs ${mono ? 'hw-mono' : ''} ${onClick ? 'hover:text-primary' : ''}`}>{label}</span>
          <span className="hw-tabular shrink-0 text-[11px] text-muted-foreground">{fmt(count)}</span>
        </div>
        <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-secondary">
          <div className="h-full rounded-full bg-primary" style={{ width: `${Math.max(3, (count / max) * 100)}%` }} />
        </div>
      </div>
    </div>
  );
}

export default function Ndr() {
  const [range, setRange] = useState<Range>('24h');
  const [d, setD] = useState<NdrOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  async function load(r: Range) {
    setLoading(true); setError(null);
    try { setD(await ndrApi.overview(r)); }
    catch (e) { setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo cargar la vista de red'); }
    finally { setLoading(false); }
  }
  useEffect(() => { load(range); }, [range]);

  const maxTalker = Math.max(1, ...(d?.topTalkers ?? []).map((t) => t.sessions));
  const maxDomain = Math.max(1, ...(d?.topDomains ?? []).map((x) => x.count));
  const maxApp = Math.max(1, ...(d?.topApps ?? []).map((x) => x.count));

  return (
    <div className="mx-auto max-w-6xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 hw-mono text-2xl font-bold tracking-tight"><Network className="h-6 w-6 text-neon" /> NDR · Red</h1>
          <p className="text-sm text-muted-foreground">Visibilidad de red desde el FortiGate: quién habla con quién, dominios, apps e IPS</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex overflow-hidden rounded-md border border-input">
            {RANGES.map((r) => <button key={r} onClick={() => setRange(r)} className={`px-3 py-1.5 text-xs ${range === r ? 'bg-secondary font-semibold text-foreground' : 'text-muted-foreground hover:bg-secondary/50'}`}>{r}</button>)}
          </div>
          <Button variant="outline" size="sm" onClick={() => load(range)} disabled={loading}><RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} /></Button>
        </div>
      </div>

      {error && <Card><CardContent className="p-4 text-sm text-amber-700">{error}</CardContent></Card>}

      {loading && !d ? (
        <p className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Cargando telemetría de red…</p>
      ) : d && (
        <>
          {/* KPIs */}
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
            <Kpi label="Sesiones" value={fmt(d.sessions)} />
            <Kpi label="Dominios distintos" value={fmt(d.distinctDomains)} />
            <Kpi label="IPs destino" value={fmt(d.distinctDstIps)} />
            <Kpi label="Alertas IPS" value={fmt(d.ipsCount)} danger={d.ipsCount > 0} />
            <Kpi label="Transferencias grandes" value={fmt(d.largeTransferCount)} danger={d.largeTransferCount > 0} />
          </div>

          {/* IOC hits (si hay) */}
          {d.iocHits.length > 0 && (
            <Card className="border-destructive/40 bg-destructive/[0.04]"><CardContent className="p-4">
              <p className="mb-2 flex items-center gap-2 text-sm font-semibold text-destructive"><ShieldAlert className="h-4 w-4" /> Tráfico hacia IOCs conocidos ({d.iocHits.length})</p>
              <div className="flex flex-wrap gap-2">
                {d.iocHits.map((h, i) => (
                  <span key={i} onClick={() => navigate(h.seen === 'ip' ? `/alertas?srcip=${encodeURIComponent(h.value)}` : `/alertas?q=${encodeURIComponent(h.value)}`)}
                    className="hw-mono cursor-pointer rounded border border-destructive/30 bg-destructive/10 px-2 py-1 text-xs text-destructive hover:bg-destructive/20">
                    {h.value} <span className="text-destructive/60">· {h.source} · conf {h.confidence}</span>
                  </span>
                ))}
              </div>
            </CardContent></Card>
          )}

          {/* Transferencias salientes grandes (posible exfiltración) */}
          {d.largeTransfers.length > 0 && (
            <Card className="border-warn-orange/40 bg-warn-orange/[0.04]"><CardContent className="p-4">
              <p className="mb-2 flex items-center gap-2 text-sm font-semibold" style={{ color: 'hsl(var(--warn-orange))' }}>
                <Upload className="h-4 w-4" /> Transferencias salientes grandes · posible exfiltración ({d.largeTransferCount})
              </p>
              <div className="space-y-2">
                {d.largeTransfers.map((t, i) => {
                  const vv = VERDICT_VAR[t.dstVerdict ?? ''] ?? 'muted-foreground';
                  const go = () => navigate(t.srcHost ? `/alertas?agent=${encodeURIComponent(t.srcHost)}` : `/alertas?srcip=${encodeURIComponent(t.srcip ?? '')}`);
                  return (
                    <div key={i} className="hw-clip flex flex-wrap items-center gap-3 border border-border bg-secondary/20 p-2.5">
                      {/* subida + veredicto */}
                      <div className="flex w-24 shrink-0 flex-col items-center gap-0.5">
                        <span className="hw-tabular text-base font-bold" style={{ color: 'hsl(var(--warn-orange))' }}>↑ {fmtBytes(t.sentbyte)}</span>
                        {t.dstVerdict && <span className="rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase" style={{ color: `hsl(var(--${vv}))`, background: `hsl(var(--${vv}) / .12)` }}>{t.dstVerdict}</span>}
                      </div>
                      {/* origen (PC + usuario) */}
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="truncate text-sm font-semibold">{t.srcHost ?? t.srcip}</span>
                          {t.srcUser && <span className="hw-mono rounded bg-primary/12 px-1.5 py-0.5 text-[10px] text-primary">👤 {t.srcUser}</span>}
                        </div>
                        <p className="hw-mono truncate text-[10px] text-muted-foreground">{t.srcip}{t.srcOs ? ` · ${t.srcOs}` : ''}</p>
                      </div>
                      <span className="shrink-0 text-muted-foreground">→</span>
                      {/* destino */}
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <Globe2 className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                          <span className="truncate text-sm font-medium">{t.dstDomain ?? t.dstip}</span>
                          {t.dstIoc && <span className="rounded bg-destructive/15 px-1 py-0.5 text-[9px] font-semibold text-destructive">IOC</span>}
                          {t.dstAbuse != null && t.dstAbuse > 0 && <span className="rounded bg-destructive/15 px-1 py-0.5 text-[9px] font-semibold text-destructive">abuse {t.dstAbuse}</span>}
                        </div>
                        <p className="hw-mono truncate text-[10px] text-muted-foreground">{t.dstip}{t.dstport ? `:${t.dstport}` : ''} · {t.service ?? '—'}{t.dstcountry ? ` · ${t.dstcountry}` : ''}{t.dstIsp ? ` · ${t.dstIsp}` : ''}</p>
                      </div>
                      {/* hora + accion */}
                      <div className="flex shrink-0 flex-col items-end gap-1">
                        <span className="hw-tabular text-[10px] text-muted-foreground">↓ {fmtBytes(t.rcvdbyte)} · {new Date(t.ts).toLocaleTimeString('es-CO', { hour: '2-digit', minute: '2-digit' })}</span>
                        <button onClick={go} className="hw-mono text-[10px] text-primary hover:underline">investigar →</button>
                      </div>
                    </div>
                  );
                })}
              </div>
              <p className="mt-2 text-[10px] text-muted-foreground/70">Sesiones con subida ≥ 10 MB (regla 100600 · MITRE T1048). Origen/usuario por correlación con agentes Wazuh; reputación del destino vía AbuseIPDB. El contenido va cifrado (no hay DLP) — el servicio/dominio es el indicio.</p>
            </CardContent></Card>
          )}

          <div className="grid gap-4 lg:grid-cols-2">
            {/* Top talkers */}
            <Card><CardContent className="p-4">
              <p className="mb-3 text-sm font-semibold">Top talkers (orígenes más activos)</p>
              <div className="space-y-2.5">
                {d.topTalkers.map((t) => (
                  <div key={t.ip} className="flex items-center gap-2 cursor-pointer" onClick={() => navigate(`/alertas?srcip=${encodeURIComponent(t.ip)}`)} title={`Ver alertas de ${t.ip}`}>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center justify-between gap-2">
                        <span className="hw-mono truncate text-xs hover:text-primary">{t.ip}</span>
                        <span className="hw-tabular shrink-0 text-[11px] text-muted-foreground">{fmt(t.sessions)} ses · {t.dstIps} dst</span>
                      </div>
                      <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-secondary"><div className="h-full rounded-full bg-primary" style={{ width: `${Math.max(3, (t.sessions / maxTalker) * 100)}%` }} /></div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent></Card>

            {/* Top dominios */}
            <Card><CardContent className="p-4">
              <p className="mb-3 flex items-center gap-2 text-sm font-semibold"><Globe2 className="h-4 w-4 text-muted-foreground" /> Dominios más visitados (SNI)</p>
              <div className="space-y-2.5">
                {d.topDomains.map((x) => <BarRow key={x.domain} label={x.domain} count={x.count} max={maxDomain} mono onClick={() => navigate(`/alertas?q=${encodeURIComponent(x.domain)}`)} />)}
              </div>
            </CardContent></Card>

            {/* Top apps */}
            <Card><CardContent className="p-4">
              <p className="mb-3 text-sm font-semibold">Aplicaciones</p>
              <div className="space-y-2.5">
                {d.topApps.map((x) => <BarRow key={x.app} label={x.app} count={x.count} max={maxApp} />)}
              </div>
            </CardContent></Card>

            {/* IPS alerts */}
            <Card><CardContent className="p-4">
              <p className="mb-3 flex items-center gap-2 text-sm font-semibold"><ShieldAlert className="h-4 w-4 text-muted-foreground" /> Alertas IPS recientes</p>
              {d.ipsAlerts.length === 0 ? (
                <p className="py-6 text-center text-xs text-muted-foreground">Sin alertas IPS en el rango.</p>
              ) : (
                <div className="max-h-[280px] space-y-1.5 overflow-y-auto">
                  {d.ipsAlerts.map((a, i) => (
                    <div key={i} className="rounded border-l-2 border-l-destructive/60 bg-secondary/30 px-2.5 py-1.5">
                      <div className="flex items-center justify-between gap-2">
                        <span className="truncate text-xs font-medium">{a.attack || a.msg}</span>
                        {a.severity && <span className="hw-mono shrink-0 text-[9px] uppercase text-destructive">{a.severity}</span>}
                      </div>
                      <p className="hw-mono truncate text-[10px] text-muted-foreground">{a.srcip} → {a.dstip} · {a.action} · {new Date(a.ts).toLocaleTimeString('es-CO')}</p>
                    </div>
                  ))}
                </div>
              )}
            </CardContent></Card>
          </div>

          <p className="text-center text-[11px] text-muted-foreground/60">
            Fuente: FortiGate (Application Control + IPS) vía Wazuh. Nota: el DNS va cifrado (DoH/DoT) en los equipos, por eso los dominios se ven por el SNI del tráfico TLS. Actualizado {new Date(d.generatedAt).toLocaleTimeString('es-CO')}.
          </p>
        </>
      )}
    </div>
  );
}
