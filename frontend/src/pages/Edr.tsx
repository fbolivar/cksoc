/**
 * EDR / NGAV — conector a la protección de endpoint del cliente (Defender /
 * SentinelOne). Consume alertas + salud de dispositivos y expone acciones de
 * respuesta (aislar/reconectar/escanear). No construimos AV; integramos el suyo.
 */
import { useEffect, useState } from 'react';
import { AxiosError } from 'axios';
import { Cpu, Loader2, RefreshCw, ShieldAlert, ShieldOff, Radiation, Power, ScanLine, Server } from 'lucide-react';
import { edrApi, type EdrOverview, type EdrDevice, type EdrSev } from '@/lib/edr';
import { useAuth } from '@/lib/auth';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

const SEV_COLOR: Record<EdrSev, string> = { critica: 'destructive', alta: 'warn-orange', media: 'primary', baja: 'cyan', info: 'muted-foreground' };
function fmt(ts: string) { return ts ? new Date(ts).toLocaleString('es-CO') : ''; }
function SevPill({ sev }: { sev: EdrSev }) {
  const c = SEV_COLOR[sev];
  return <span className="hw-mono inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-bold uppercase" style={{ background: `hsl(var(--${c}) / .16)`, color: `hsl(var(--${c}))` }}>{sev}</span>;
}

export default function Edr() {
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';
  const [ov, setOv] = useState<EdrOverview | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  const flash = (kind: 'ok' | 'err', text: string) => { setMsg({ kind, text }); setTimeout(() => setMsg(null), 5000); };
  const err = (e: unknown, fb: string) => flash('err', (e as AxiosError<{ error?: string }>).response?.data?.error ?? fb);

  async function reload() { setOv(await edrApi.overview()); }
  useEffect(() => { reload().catch(() => flash('err', 'No se pudo cargar')); /* eslint-disable-next-line */ }, []);

  async function action(kind: 'isolate' | 'unisolate' | 'scan', d: EdrDevice) {
    const label = kind === 'isolate' ? `aislar ${d.name}` : kind === 'unisolate' ? `reconectar ${d.name}` : `escanear ${d.name}`;
    if (!confirm(`¿Confirmas ${label}?`)) return;
    setBusy(d.id + kind);
    try { await edrApi[kind](d.id); flash('ok', `Acción enviada: ${label}`); await reload(); }
    catch (e) { err(e, 'No se pudo ejecutar la acción'); } finally { setBusy(null); }
  }

  const st = ov?.status; const k = ov?.kpis;
  const provLabel = st?.provider === 'sentinelone' ? 'SentinelOne' : st?.provider === 'defender' ? 'Microsoft Defender' : '—';

  return (
    <div className="mx-auto max-w-5xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="hw-mono flex items-center gap-2 text-2xl font-bold tracking-tight">
            <Cpu className="h-6 w-6 text-primary" /> EDR · ENDPOINT
          </h1>
          <p className="hw-mono text-[11px] tracking-wide text-muted-foreground">
            NGAV DEL CLIENTE // ALERTAS · SALUD · AISLAR / ESCANEAR
          </p>
        </div>
        {st?.configured && <Button size="sm" variant="outline" onClick={() => reload()}><RefreshCw className="h-4 w-4" /> Actualizar</Button>}
      </div>

      {msg && (
        <div className={`rounded-md border px-3 py-2 text-sm ${msg.kind === 'ok'
          ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200'
          : 'border-destructive/40 bg-destructive/10 text-destructive'}`}>{msg.text}</div>
      )}

      {!ov ? (
        <p className="py-8 text-center text-sm text-muted-foreground"><Loader2 className="mr-2 inline h-4 w-4 animate-spin" /> Cargando…</p>
      ) : !st?.configured ? (
        /* Guía de activación (conector on-demand) */
        <Card>
          <CardContent className="space-y-3 p-5">
            <p className="flex items-center gap-2 text-sm font-semibold"><ShieldOff className="h-4 w-4 text-amber-500" /> Conector de EDR sin activar (a demanda)</p>
            <p className="text-[13px] text-muted-foreground">
              HexWatch no reemplaza tu antivirus: <b>integra el EDR/NGAV del cliente</b> y consume su telemetría
              (alertas + salud de equipos), y te deja aislar o escanear equipos desde aquí. Se activa poniendo las
              credenciales del cliente en el <span className="hw-mono">.env</span> del backend:
            </p>
            <div className="grid gap-2 sm:grid-cols-2">
              <div className="rounded-md border border-border/60 p-3">
                <p className="mb-1 text-xs font-semibold">SentinelOne</p>
                <p className="hw-mono text-[11px] text-muted-foreground">S1_URL=https://tuconsola.sentinelone.net<br />S1_TOKEN=&lt;API token&gt;</p>
              </div>
              <div className="rounded-md border border-border/60 p-3">
                <p className="mb-1 text-xs font-semibold">Microsoft Defender (MDE)</p>
                <p className="hw-mono text-[11px] text-muted-foreground">MDE_TENANT_ID=…<br />MDE_CLIENT_ID=…<br />MDE_CLIENT_SECRET=…<br /><span className="text-muted-foreground/70">(app con permisos WindowsDefenderATP: Alert.Read.All, Machine.*)</span></p>
              </div>
            </div>
            <p className="text-[11px] text-muted-foreground">Al guardar y reiniciar, este panel muestra automáticamente las alertas y los equipos.</p>
          </CardContent>
        </Card>
      ) : !st.reachable ? (
        <Card><CardContent className="p-5 text-sm">
          <p className="flex items-center gap-2 font-semibold text-destructive"><ShieldAlert className="h-4 w-4" /> {provLabel} configurado pero no alcanzable</p>
          <p className="mt-1 text-[12px] text-muted-foreground">Error: {st.error ?? 'desconocido'}. Revisa la URL/credenciales y los permisos.</p>
        </CardContent></Card>
      ) : (
        <>
          <div className="text-[11px] text-muted-foreground">Proveedor: <b className="text-foreground">{provLabel}</b> · conectado</div>
          {/* KPIs */}
          <div className="grid gap-3 sm:grid-cols-5">
            {[
              { icon: ShieldAlert, col: 'destructive', v: k?.criticas ?? 0, l: 'Alertas críticas/altas' },
              { icon: Radiation, col: 'warn-orange', v: k?.alertas ?? 0, l: 'Alertas totales' },
              { icon: Server, col: 'primary', v: k?.dispositivos ?? 0, l: 'Dispositivos' },
              { icon: ShieldOff, col: 'cyan', v: k?.aislados ?? 0, l: 'Aislados' },
              { icon: Radiation, col: 'destructive', v: k?.enRiesgo ?? 0, l: 'En riesgo' },
            ].map((x) => (
              <div key={x.l} className="hud">
                <span className="hw-clip mb-2 flex h-9 w-9 items-center justify-center" style={{ background: `hsl(var(--${x.col}) / .14)`, color: `hsl(var(--${x.col}))` }}><x.icon className="h-[18px] w-[18px]" /></span>
                <div className="text-2xl font-bold">{x.v.toLocaleString('es-CO')}</div>
                <div className="text-[11px] text-muted-foreground">{x.l}</div>
              </div>
            ))}
          </div>

          {/* Alertas */}
          <Card>
            <CardHeader><CardTitle className="text-muted-foreground">Alertas del EDR ({ov.alerts.length})</CardTitle></CardHeader>
            <CardContent>
              {ov.alerts.length === 0 ? <p className="py-4 text-center text-sm text-muted-foreground">Sin alertas recientes. 👍</p> : (
                <div className="overflow-x-auto"><table className="w-full text-sm"><thead>
                  <tr className="border-b border-border/60 text-left text-xs text-muted-foreground"><th className="pb-2 pr-3">Sev.</th><th className="pb-2 pr-3">Amenaza</th><th className="pb-2 pr-3">Equipo</th><th className="pb-2 pr-3">Estado</th><th className="pb-2 text-right">Fecha</th></tr>
                </thead><tbody>
                  {ov.alerts.map((a) => (
                    <tr key={a.id} className="border-b border-border/30 last:border-0">
                      <td className="py-2 pr-3"><SevPill sev={a.severity} /></td>
                      <td className="py-2 pr-3">{a.title}{a.category && <span className="ml-1 text-[11px] text-muted-foreground">· {a.category}</span>}</td>
                      <td className="py-2 pr-3 font-mono text-[12px]">{a.device}</td>
                      <td className="py-2 pr-3 text-[12px] text-muted-foreground">{a.status}</td>
                      <td className="py-2 text-right text-[11px] text-muted-foreground">{fmt(a.createdAt)}</td>
                    </tr>
                  ))}
                </tbody></table></div>
              )}
            </CardContent>
          </Card>

          {/* Dispositivos */}
          <Card>
            <CardHeader><CardTitle className="text-muted-foreground">Dispositivos ({ov.devices.length})</CardTitle></CardHeader>
            <CardContent>
              {ov.devices.length === 0 ? <p className="py-4 text-center text-sm text-muted-foreground">Sin dispositivos.</p> : (
                <div className="overflow-x-auto"><table className="w-full text-sm"><thead>
                  <tr className="border-b border-border/60 text-left text-xs text-muted-foreground"><th className="pb-2 pr-3">Equipo</th><th className="pb-2 pr-3">SO</th><th className="pb-2 pr-3">Salud</th><th className="pb-2 pr-3">Riesgo</th><th className="pb-2 pr-3">Estado</th><th className="pb-2 text-right">Acciones</th></tr>
                </thead><tbody>
                  {ov.devices.map((d) => (
                    <tr key={d.id} className="border-b border-border/30 last:border-0">
                      <td className="py-2 pr-3 font-mono text-[12px]">{d.name}</td>
                      <td className="py-2 pr-3 text-[12px] text-muted-foreground">{d.os}</td>
                      <td className="py-2 pr-3 text-[12px]">{d.health}</td>
                      <td className="py-2 pr-3 text-[12px]">{d.riskLevel}</td>
                      <td className="py-2 pr-3">{d.isolated ? <span className="rounded bg-destructive/15 px-1.5 py-0.5 text-[10px] text-destructive">aislado</span> : <span className="text-[11px] text-muted-foreground">en red</span>}</td>
                      <td className="py-2">
                        <div className="flex justify-end gap-1">
                          {isAdmin ? (<>
                            {d.isolated
                              ? <Button variant="ghost" size="icon" title="Reconectar" disabled={busy === d.id + 'unisolate'} onClick={() => action('unisolate', d)}>{busy === d.id + 'unisolate' ? <Loader2 className="h-4 w-4 animate-spin" /> : <Power className="h-4 w-4" />}</Button>
                              : <Button variant="ghost" size="icon" title="Aislar de la red" disabled={busy === d.id + 'isolate'} onClick={() => action('isolate', d)}>{busy === d.id + 'isolate' ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldOff className="h-4 w-4 text-red-400" />}</Button>}
                            <Button variant="ghost" size="icon" title="Escaneo antivirus" disabled={busy === d.id + 'scan'} onClick={() => action('scan', d)}>{busy === d.id + 'scan' ? <Loader2 className="h-4 w-4 animate-spin" /> : <ScanLine className="h-4 w-4" />}</Button>
                          </>) : <span className="text-[10px] text-muted-foreground">solo admin</span>}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody></table></div>
              )}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
