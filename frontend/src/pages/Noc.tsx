/**
 * NOC — Monitoreo de disponibilidad (uptime). Estado up/down, latencia, grupos,
 * uptime % histórico, métricas SNMP-lite (CPU/RAM/interfaces/temperatura),
 * alta/baja de objetivos, reportes y bitácora de transiciones. Refresca cada 20s.
 */
import { useEffect, useState, useCallback, Fragment } from 'react';
import { AxiosError } from 'axios';
import {
  Activity, RefreshCw, Loader2, Plus, Trash2, Server, Globe2, Gauge, CircleCheck, CircleX, Power, Network,
  Cpu, MemoryStick, Thermometer, Cable, Radio, BarChart3, ShieldCheck,
} from 'lucide-react';
import { nocApi, type NocOverview, type NocReport, type NocTarget, type CheckKind } from '@/lib/noc';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

function Kpi({ icon: Icon, label, value, tone }: { icon: typeof Gauge; label: string; value: number | string; tone?: 'ok' | 'danger' | 'warn' }) {
  const color = tone === 'danger' ? 'hsl(var(--destructive))' : tone === 'warn' ? 'hsl(38 92% 50%)' : tone === 'ok' ? 'hsl(152 65% 45%)' : 'hsl(var(--primary))';
  return (
    <Card><CardContent className="flex items-center gap-3 p-4">
      <Icon className="h-6 w-6" style={{ color }} />
      <div><div className="hw-mono text-2xl font-bold tabular-nums" style={{ color }}>{value}</div>
        <div className="hw-mono text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div></div>
    </CardContent></Card>
  );
}
function Dot({ s }: { s: NocTarget['status'] }) {
  const c = s === 'up' ? 'hsl(152 65% 45%)' : s === 'down' ? 'hsl(var(--destructive))' : 'hsl(var(--muted-foreground))';
  return <span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: c, boxShadow: `0 0 6px ${c}` }} />;
}
function fmt(ts: string | null): string { return ts ? ts.slice(0, 16).replace('T', ' ') : '—'; }
function sinceTxt(ts: string | null): string {
  if (!ts) return '—';
  const min = Math.round((Date.now() - Date.parse(ts)) / 60000);
  if (min < 60) return `${min}m`; if (min < 1440) return `${Math.round(min / 60)}h`; return `${Math.round(min / 1440)}d`;
}
function upColor(pct: number | null | undefined): string {
  if (pct == null) return 'hsl(var(--muted-foreground))';
  if (pct >= 99.9) return 'hsl(152 65% 45%)';
  if (pct >= 99) return 'hsl(152 50% 55%)';
  if (pct >= 95) return 'hsl(38 92% 50%)';
  return 'hsl(var(--destructive))';
}
function upTxt(pct: number | null | undefined): string { return pct == null ? '—' : `${pct.toFixed(pct >= 99.95 ? 0 : 2)}%`; }
function dur(s: number | null): string {
  if (s == null) return '—';
  const d = Math.floor(s / 86400); const h = Math.floor((s % 86400) / 3600); const m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`; if (h > 0) return `${h}h ${m}m`; return `${m}m`;
}
function Metric({ icon: Icon, val, tone }: { icon: typeof Cpu; val: string; tone?: boolean }) {
  return <span className="hw-mono inline-flex items-center gap-1 text-[10px] text-muted-foreground"><Icon className="h-3 w-3" style={tone ? { color: 'hsl(38 92% 50%)' } : undefined} />{val}</span>;
}

export default function Noc() {
  const [ov, setOv] = useState<NocOverview | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ k: 'ok' | 'err'; t: string } | null>(null);
  const [showAdd, setShowAdd] = useState(false);
  const [f, setF] = useState<{ name: string; host: string; kind: CheckKind; port: string; path: string; grupo: string; snmp: boolean; comm: string }>({ name: '', host: '', kind: 'icmp', port: '', path: '', grupo: 'Red cliente', snmp: false, comm: 'public' });
  const [rep, setRep] = useState<NocReport | null>(null);
  const [repDays, setRepDays] = useState(30);
  const [repBusy, setRepBusy] = useState(false);

  const flash = (k: 'ok' | 'err', t: string) => { setMsg({ k, t }); setTimeout(() => setMsg(null), 4000); };
  const reload = useCallback(async () => {
    try { setOv(await nocApi.overview()); } catch (e) { flash('err', (e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo cargar'); }
  }, []);
  useEffect(() => { void reload(); const i = setInterval(() => void reload(), 20_000); return () => clearInterval(i); }, [reload]);

  const loadReport = useCallback(async (days: number) => {
    setRepBusy(true); setRepDays(days);
    try { setRep(await nocApi.report(days)); } catch { flash('err', 'No se pudo cargar el reporte'); } finally { setRepBusy(false); }
  }, []);
  useEffect(() => { void loadReport(30); }, [loadReport]);

  async function checkNow() { setBusy('check'); try { await nocApi.checkNow(); await reload(); flash('ok', 'Chequeo ejecutado'); } catch { flash('err', 'Error al chequear'); } finally { setBusy(null); } }
  async function add() {
    if (!f.name.trim() || !f.host.trim()) return flash('err', 'Nombre y host requeridos');
    setBusy('add');
    try {
      await nocApi.add({ name: f.name, host: f.host, kind: f.kind, port: f.kind === 'tcp' ? Number(f.port) : null, path: f.kind === 'http' ? f.path : null, grupo: f.grupo, snmpEnabled: f.snmp, snmpCommunity: f.snmp ? f.comm : undefined });
      setF({ name: '', host: '', kind: 'icmp', port: '', path: '', grupo: f.grupo, snmp: false, comm: 'public' }); setShowAdd(false); await reload(); flash('ok', 'Objetivo agregado');
    } catch (e) { flash('err', (e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo agregar'); } finally { setBusy(null); }
  }
  async function toggle(t: NocTarget) { setBusy(t.id); try { await nocApi.toggle(t.id, !t.enabled); await reload(); } catch { flash('err', 'No se pudo cambiar'); } finally { setBusy(null); } }
  async function del(t: NocTarget) { if (!confirm(`¿Eliminar "${t.name}" del monitoreo?`)) return; setBusy(t.id); try { await nocApi.remove(t.id); await reload(); } catch { flash('err', 'No se pudo eliminar'); } finally { setBusy(null); } }
  async function snmp(t: NocTarget) {
    setBusy(t.id);
    try {
      if (t.snmp_enabled) { await nocApi.setSnmp(t.id, false); flash('ok', 'SNMP desactivado'); }
      else { const c = window.prompt(`Community SNMP (v2c) para "${t.name}":`, 'public'); if (c == null) { setBusy(null); return; } await nocApi.setSnmp(t.id, true, c.trim() || 'public'); flash('ok', 'SNMP activado (se poblará en el próximo chequeo)'); }
      await reload();
    } catch { flash('err', 'No se pudo cambiar SNMP'); } finally { setBusy(null); }
  }

  const k = ov?.kpis;
  return (
    <div className="mx-auto max-w-6xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="hw-mono flex items-center gap-2 text-2xl font-bold tracking-tight"><Activity className="h-6 w-6 text-primary" /> NOC · DISPONIBILIDAD</h1>
          <p className="hw-mono text-[11px] tracking-wide text-muted-foreground">UPTIME // ICMP · TCP · HTTP · SNMP // LATENCIA · HISTÓRICO · TRANSICIONES{ov?.lastRun ? ` // último: ${fmt(ov.lastRun)}` : ''}</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => setShowAdd((v) => !v)}><Plus className="h-4 w-4" /> Agregar</Button>
          <Button variant="outline" size="sm" onClick={checkNow} disabled={busy === 'check'}>{busy === 'check' ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />} Chequear</Button>
        </div>
      </div>
      {msg && <div className={`hw-mono rounded border p-2 text-xs ${msg.k === 'ok' ? 'border-emerald-500/40 text-emerald-400' : 'border-destructive/40 text-destructive'}`}>{msg.t}</div>}

      <div className="grid grid-cols-2 gap-3 md:grid-cols-6">
        <Kpi icon={Server} label="Objetivos" value={k?.total ?? 0} />
        <Kpi icon={CircleCheck} label="Activos" value={k?.up ?? 0} tone="ok" />
        <Kpi icon={CircleX} label="Caídos" value={k?.down ?? 0} tone={k && k.down > 0 ? 'danger' : 'ok'} />
        <Kpi icon={Gauge} label="Latencia prom (ms)" value={k?.avgLatency ?? '—'} />
        <Kpi icon={ShieldCheck} label="Uptime 30d prom" value={k?.avgUptime30 != null ? `${k.avgUptime30.toFixed(2)}%` : '—'} tone={k?.avgUptime30 != null && k.avgUptime30 < 99 ? 'warn' : 'ok'} />
        <Kpi icon={Power} label="Deshabilitados" value={k?.disabled ?? 0} tone={k && k.disabled > 0 ? 'warn' : undefined} />
      </div>

      {showAdd && (
        <Card><CardHeader><CardTitle className="hw-mono flex items-center gap-2 text-sm"><Plus className="h-4 w-4" /> AGREGAR OBJETIVO</CardTitle></CardHeader>
          <CardContent className="grid gap-2 sm:grid-cols-6">
            <input className="rounded border border-border bg-background p-2 text-sm sm:col-span-2" placeholder="Nombre (ej. Switch Recepción)" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} />
            <input className="rounded border border-border bg-background p-2 text-sm sm:col-span-2" placeholder="IP o host (ej. 192.168.2.50)" value={f.host} onChange={(e) => setF({ ...f, host: e.target.value })} />
            <select className="rounded border border-border bg-background p-2 text-sm" value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value as CheckKind })}>
              <option value="icmp">ICMP (ping)</option><option value="tcp">TCP (puerto)</option><option value="http">HTTP(S)</option>
            </select>
            {f.kind === 'tcp' && <input className="rounded border border-border bg-background p-2 text-sm" placeholder="Puerto (ej. 443)" value={f.port} onChange={(e) => setF({ ...f, port: e.target.value })} />}
            {f.kind === 'http' && <input className="rounded border border-border bg-background p-2 text-sm" placeholder="Ruta (ej. /health)" value={f.path} onChange={(e) => setF({ ...f, path: e.target.value })} />}
            <input className="rounded border border-border bg-background p-2 text-sm sm:col-span-2" placeholder="Grupo (ej. Red cliente)" value={f.grupo} onChange={(e) => setF({ ...f, grupo: e.target.value })} />
            <label className="hw-mono flex items-center gap-2 text-xs text-muted-foreground sm:col-span-2"><input type="checkbox" checked={f.snmp} onChange={(e) => setF({ ...f, snmp: e.target.checked })} /> <Radio className="h-3.5 w-3.5" /> SNMP-lite (CPU/RAM/interfaces)</label>
            {f.snmp && <input className="rounded border border-border bg-background p-2 text-sm sm:col-span-2" placeholder="Community (v2c, ej. public)" value={f.comm} onChange={(e) => setF({ ...f, comm: e.target.value })} />}
            <Button onClick={add} disabled={busy === 'add'} className="sm:col-span-1">{busy === 'add' ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />} Agregar</Button>
          </CardContent>
        </Card>
      )}

      {(ov?.grupos ?? []).map((g) => (
        <Card key={g.grupo}>
          <CardHeader><CardTitle className="hw-mono flex items-center gap-2 text-sm">
            <Network className="h-4 w-4" /> {g.grupo.toUpperCase()}
            {g.esCliente && <span className="hw-mono rounded bg-amber-500/15 px-1.5 py-0.5 text-[9px] uppercase text-amber-400">cliente</span>}
            <span className="text-[10px] text-muted-foreground">({g.targets.filter((t) => t.enabled && t.status === 'up').length}/{g.targets.filter((t) => t.enabled).length} arriba)</span>
          </CardTitle></CardHeader>
          <CardContent className="overflow-x-auto p-0">
            <table className="w-full text-sm">
              <thead className="hw-mono text-[10px] uppercase text-muted-foreground"><tr className="border-b border-border">
                <th className="px-3 py-2 text-left">Estado</th><th className="px-3 py-2 text-left">Nombre</th><th className="px-3 py-2 text-left">Host</th><th className="px-3 py-2 text-left">Chequeo</th><th className="px-3 py-2 text-right">Latencia</th><th className="px-3 py-2 text-right">Uptime 30d</th><th className="px-3 py-2 text-left">Desde</th><th className="px-3 py-2 text-right">Acciones</th>
              </tr></thead>
              <tbody>
                {g.targets.map((t) => (
                  <Fragment key={t.id}>
                    <tr className={`border-b border-border/50 ${!t.enabled ? 'opacity-50' : t.status === 'down' ? 'bg-destructive/10' : ''} ${t.snmp_enabled ? 'border-b-0' : ''}`}>
                      <td className="px-3 py-1.5"><Dot s={t.enabled ? t.status : 'unknown'} /> <span className="hw-mono ml-1 text-[11px] uppercase text-muted-foreground">{t.enabled ? t.status : 'off'}</span></td>
                      <td className="px-3 py-1.5 font-medium">{t.name}</td>
                      <td className="hw-mono px-3 py-1.5 text-xs text-muted-foreground">{t.host}{t.port ? `:${t.port}` : ''}{t.path ?? ''}</td>
                      <td className="px-3 py-1.5 text-xs uppercase text-muted-foreground">{t.kind}{t.snmp_enabled ? ' +snmp' : ''}</td>
                      <td className="px-3 py-1.5 text-right tabular-nums">{t.latency_ms != null ? `${t.latency_ms} ms` : '—'}</td>
                      <td className="hw-mono px-3 py-1.5 text-right tabular-nums" style={{ color: upColor(t.uptime?.d30) }}>{upTxt(t.uptime?.d30)}</td>
                      <td className="px-3 py-1.5 text-xs text-muted-foreground">{sinceTxt(t.since)}</td>
                      <td className="px-3 py-1.5 text-right">
                        <button className={`mr-2 ${t.snmp_enabled ? 'text-primary' : 'text-muted-foreground hover:text-foreground'}`} title={t.snmp_enabled ? 'SNMP activo (clic para desactivar)' : 'Activar SNMP-lite'} onClick={() => snmp(t)} disabled={busy === t.id}><Radio className="inline h-4 w-4" /></button>
                        <button className="mr-2 text-muted-foreground hover:text-foreground" title={t.enabled ? 'Deshabilitar' : 'Habilitar'} onClick={() => toggle(t)} disabled={busy === t.id}><Power className="inline h-4 w-4" /></button>
                        <button className="text-muted-foreground hover:text-destructive" title="Eliminar" onClick={() => del(t)} disabled={busy === t.id}><Trash2 className="inline h-4 w-4" /></button>
                      </td>
                    </tr>
                    {t.snmp_enabled && (
                      <tr className={`border-b border-border/50 ${!t.enabled ? 'opacity-50' : ''}`}>
                        <td />
                        <td colSpan={7} className="px-3 pb-2 pt-0">
                          <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
                            {t.cpu_pct != null && <Metric icon={Cpu} val={`CPU ${t.cpu_pct}%`} tone={t.cpu_pct >= 85} />}
                            {t.mem_pct != null && <Metric icon={MemoryStick} val={`RAM ${t.mem_pct}%`} tone={t.mem_pct >= 90} />}
                            {t.if_total != null && <Metric icon={Cable} val={`IF ${t.if_up ?? 0}/${t.if_total}`} tone={t.if_up != null && t.if_total != null && t.if_up < t.if_total} />}
                            {t.uptime_s != null && <Metric icon={Activity} val={`up ${dur(t.uptime_s)}`} />}
                            {t.temp_c != null && <Metric icon={Thermometer} val={`${t.temp_c}°C`} tone={t.temp_c >= 65} />}
                            {t.sys_descr && <span className="hw-mono truncate text-[10px] text-muted-foreground/70" style={{ maxWidth: 420 }} title={t.sys_descr}>· {t.sys_descr}</span>}
                            {t.cpu_pct == null && t.mem_pct == null && t.if_total == null && t.uptime_s == null && !t.sys_descr && <span className="hw-mono text-[10px] text-muted-foreground/70">SNMP activo · sin datos aún (se puebla en el próximo chequeo; verifica community y acceso).</span>}
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
                {g.targets.length === 0 && <tr><td colSpan={8} className="px-3 py-3 text-center text-muted-foreground">Sin objetivos.</td></tr>}
              </tbody>
            </table>
          </CardContent>
        </Card>
      ))}
      {ov && ov.grupos.length === 0 && <Card><CardContent className="p-6 text-center text-muted-foreground">Aún no hay objetivos. Usa <b>Agregar</b> para monitorear un dispositivo o servicio.</CardContent></Card>}

      {/* Reporte de uptime histórico */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="hw-mono flex items-center gap-2 text-sm"><BarChart3 className="h-4 w-4" /> REPORTE DE DISPONIBILIDAD {rep ? `· ${rep.dias}d` : ''}</CardTitle>
          <div className="flex items-center gap-1">
            {[7, 30, 90].map((d) => (
              <button key={d} onClick={() => void loadReport(d)} disabled={repBusy}
                className={`hw-mono rounded border px-2 py-0.5 text-[11px] ${repDays === d ? 'border-primary text-primary' : 'border-border text-muted-foreground hover:text-foreground'}`}>{d}d</button>
            ))}
            {repBusy && <Loader2 className="h-3.5 w-3.5 animate-spin text-muted-foreground" />}
          </div>
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <table className="w-full text-sm">
            <thead className="hw-mono text-[10px] uppercase text-muted-foreground"><tr className="border-b border-border">
              <th className="px-3 py-2 text-left">Objetivo</th><th className="px-3 py-2 text-left">Grupo</th><th className="px-3 py-2 text-right">Uptime</th><th className="px-3 py-2 text-right">Caídas</th><th className="px-3 py-2 text-right">Downtime</th>
            </tr></thead>
            <tbody>
              {(rep?.objetivos ?? []).map((o, i) => (
                <tr key={i} className="border-b border-border/50">
                  <td className="px-3 py-1.5 font-medium">{o.name} <span className="hw-mono text-[10px] text-muted-foreground">{o.host}</span></td>
                  <td className="px-3 py-1.5 text-xs text-muted-foreground">{o.grupo}{o.esCliente ? ' · cliente' : ''}</td>
                  <td className="hw-mono px-3 py-1.5 text-right tabular-nums" style={{ color: upColor(o.uptimePct) }}>{upTxt(o.uptimePct)}</td>
                  <td className="px-3 py-1.5 text-right tabular-nums">{o.caidas}</td>
                  <td className="px-3 py-1.5 text-right tabular-nums text-muted-foreground">{o.downMin > 0 ? dur(o.downMin * 60) : '—'}</td>
                </tr>
              ))}
              {rep && rep.objetivos.length === 0 && <tr><td colSpan={5} className="px-3 py-3 text-center text-muted-foreground">Sin objetivos habilitados.</td></tr>}
            </tbody>
          </table>
        </CardContent>
      </Card>

      <Card><CardHeader><CardTitle className="hw-mono flex items-center gap-2 text-sm"><Globe2 className="h-4 w-4" /> BITÁCORA DE TRANSICIONES</CardTitle></CardHeader>
        <CardContent className="space-y-1">
          {(ov?.eventos ?? []).map((e, i) => (
            <div key={i} className="hw-mono flex items-center gap-2 text-xs">
              <Dot s={e.status} /><span className="text-muted-foreground">{fmt(e.at)}</span>
              <span className={e.status === 'down' ? 'text-destructive' : 'text-emerald-400'}>{e.status === 'down' ? 'CAÍDO' : 'OK'}</span>
              <span>{e.name}</span>{e.latency_ms != null && <span className="text-muted-foreground">· {e.latency_ms} ms</span>}
            </div>
          ))}
          {ov && ov.eventos.length === 0 && <div className="text-xs text-muted-foreground">Sin transiciones registradas aún.</div>}
        </CardContent>
      </Card>

      <p className="hw-mono flex items-center gap-1 text-[10px] text-muted-foreground"><Activity className="h-3 w-3" /> Chequeos activos (lectura) + SNMP-lite de solo lectura · refresco 20s · caídas de equipos del cliente → instructivo a soporte en sitio (Ricardo) vía CKAgentico.</p>
    </div>
  );
}
