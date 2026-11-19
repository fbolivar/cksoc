/**
 * Seguridad de IA — Inventario de IA (red) + Monitoreo de Microsoft 365 Copilot.
 * Primer bloque del Módulo de Seguridad de IA: visibilidad, gobierno y detección
 * (incluye intentos de jailbreak/prompt-injection que marca el propio Copilot).
 */
import { useEffect, useState, useCallback } from 'react';
import { AxiosError } from 'axios';
import {
  BrainCircuit, RefreshCw, Loader2, ShieldCheck, ShieldAlert, Cpu, Users, Activity, Bot, AlertTriangle, FileText, AppWindow, Clock,
} from 'lucide-react';
import { aisecApi, type AiInventory, type CopilotSummary } from '@/lib/aisec';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

const RANGES = ['24h', '7d', '30d'] as const;
type Range = (typeof RANGES)[number];

function Kpi({ icon: Icon, label, value, tone }: { icon: typeof Cpu; label: string; value: number | string; tone?: 'danger' | 'warn' | 'ok' }) {
  const color = tone === 'danger' ? 'hsl(var(--destructive))' : tone === 'warn' ? 'hsl(38 92% 50%)' : tone === 'ok' ? 'hsl(152 65% 45%)' : 'hsl(var(--primary))';
  return (
    <Card>
      <CardContent className="flex items-center gap-3 p-4">
        <Icon className="h-6 w-6" style={{ color }} />
        <div>
          <div className="hw-mono text-2xl font-bold tabular-nums" style={{ color }}>{value}</div>
          <div className="hw-mono text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div>
        </div>
      </CardContent>
    </Card>
  );
}

function Pill({ ok, children }: { ok: boolean; children: React.ReactNode }) {
  return (
    <span className="hw-mono inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide"
      style={{ background: ok ? 'hsl(152 60% 45% / .16)' : 'hsl(var(--destructive) / .16)', color: ok ? 'hsl(152 65% 55%)' : 'hsl(var(--destructive))' }}>
      {children}
    </span>
  );
}

function fmt(ts: string): string { return ts ? ts.slice(0, 16).replace('T', ' ') : '—'; }

export default function AiSecurity() {
  const [range, setRange] = useState<Range>('7d');
  const [inv, setInv] = useState<AiInventory | null>(null);
  const [cop, setCop] = useState<CopilotSummary | null>(null);
  const [loading, setLoading] = useState(false);
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  const flash = (kind: 'ok' | 'err', text: string) => { setMsg({ kind, text }); setTimeout(() => setMsg(null), 5000); };

  const reload = useCallback(async (r: Range) => {
    setLoading(true);
    try {
      const [i, c] = await Promise.all([aisecApi.inventory(r), aisecApi.copilot(r)]);
      setInv(i); setCop(c);
    } catch (e) {
      flash('err', (e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo cargar');
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { void reload(range); }, [range, reload]);

  const k = inv?.kpis;
  return (
    <div className="mx-auto max-w-6xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="hw-mono flex items-center gap-2 text-2xl font-bold tracking-tight">
            <BrainCircuit className="h-6 w-6 text-primary" /> SEGURIDAD DE IA
          </h1>
          <p className="hw-mono text-[11px] tracking-wide text-muted-foreground">
            INVENTARIO DE IA (RED) // MONITOREO DE M365 COPILOT // PROMPT-INJECTION
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="hw-mono flex overflow-hidden rounded border border-border text-xs">
            {RANGES.map((r) => (
              <button key={r} onClick={() => setRange(r)}
                className={`px-2.5 py-1 ${range === r ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:bg-muted'}`}>{r}</button>
            ))}
          </div>
          <Button variant="outline" size="sm" onClick={() => reload(range)} disabled={loading}>
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
          </Button>
        </div>
      </div>

      {msg && <div className={`hw-mono rounded border p-2 text-xs ${msg.kind === 'ok' ? 'border-emerald-500/40 text-emerald-400' : 'border-destructive/40 text-destructive'}`}>{msg.text}</div>}

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-6">
        <Kpi icon={Cpu} label="Servicios IA" value={k?.aiServices ?? 0} />
        <Kpi icon={ShieldAlert} label="Shadow (no aprob.)" value={k?.shadowServices ?? 0} tone={k && k.shadowServices > 0 ? 'warn' : 'ok'} />
        <Kpi icon={Activity} label="Interacc. Copilot" value={k?.copilotInteractions ?? 0} />
        <Kpi icon={Users} label="Usuarios Copilot" value={k?.copilotUsers ?? 0} />
        <Kpi icon={AlertTriangle} label="Jailbreak intentos" value={k?.jailbreakAttempts ?? 0} tone={k && k.jailbreakAttempts > 0 ? 'danger' : 'ok'} />
        <Kpi icon={Clock} label="Copilot fuera horario" value={cop?.offHours ?? 0} tone={cop && cop.offHours > 0 ? 'warn' : 'ok'} />
      </div>

      {/* Inventario de IA por red */}
      <Card>
        <CardHeader><CardTitle className="hw-mono flex items-center gap-2 text-sm"><Bot className="h-4 w-4" /> INVENTARIO DE IA · DETECTADO POR RED (SNI)</CardTitle></CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <table className="w-full text-sm">
            <thead className="hw-mono text-[10px] uppercase text-muted-foreground">
              <tr className="border-b border-border">
                <th className="px-3 py-2 text-left">Servicio</th><th className="px-3 py-2 text-left">Proveedor</th>
                <th className="px-3 py-2 text-right">Equipos</th><th className="px-3 py-2 text-right">Hits</th>
                <th className="px-3 py-2 text-center">Estado</th><th className="px-3 py-2 text-left">Último</th>
              </tr>
            </thead>
            <tbody>
              {(inv?.network ?? []).map((n) => (
                <tr key={n.service} className="border-b border-border/50">
                  <td className="px-3 py-1.5 font-medium">{n.name}</td>
                  <td className="px-3 py-1.5 text-muted-foreground">{n.vendor}</td>
                  <td className="px-3 py-1.5 text-right tabular-nums">{n.devices}</td>
                  <td className="px-3 py-1.5 text-right tabular-nums">{n.hits}</td>
                  <td className="px-3 py-1.5 text-center"><Pill ok={n.sanctioned}>{n.sanctioned ? 'Aprobado' : 'Shadow'}</Pill></td>
                  <td className="hw-mono px-3 py-1.5 text-xs text-muted-foreground">{fmt(n.lastSeen)}</td>
                </tr>
              ))}
              {inv && inv.network.length === 0 && <tr><td colSpan={6} className="px-3 py-4 text-center text-muted-foreground">Sin uso de IA por red en el periodo.</td></tr>}
            </tbody>
          </table>
          <p className="px-3 py-2 text-[11px] text-muted-foreground">La aprobación/sanción de cada servicio se gestiona en <b>Shadow-AI · Uso de IA</b> (comparten política).</p>
        </CardContent>
      </Card>

      {/* Copilot: jailbreak */}
      {cop && cop.jailbreakAttempts > 0 && (
        <Card className="border-destructive/50">
          <CardHeader><CardTitle className="hw-mono flex items-center gap-2 text-sm text-destructive"><AlertTriangle className="h-4 w-4" /> INTENTOS DE JAILBREAK / PROMPT-INJECTION ({cop.jailbreakAttempts})</CardTitle></CardHeader>
          <CardContent className="space-y-1">
            {cop.jailbreakList.map((j, i) => (
              <div key={i} className="hw-mono flex flex-wrap items-center gap-x-3 gap-y-0.5 text-xs">
                <span className="font-semibold text-destructive">{j.user}</span>
                <span className="text-muted-foreground">{j.app}</span>
                <span className="text-muted-foreground">{fmt(j.time)}</span>
                {j.contexts[0] && <span className="truncate text-muted-foreground">· {j.contexts[0].split('/').pop()}</span>}
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Copilot: apps + usuarios + recursos */}
      <div className="grid gap-3 md:grid-cols-3">
        <Card>
          <CardHeader><CardTitle className="hw-mono flex items-center gap-2 text-sm"><AppWindow className="h-4 w-4" /> COPILOT POR APP</CardTitle></CardHeader>
          <CardContent className="space-y-1">
            {(cop?.byApp ?? []).map((b) => (
              <div key={b.key} className="hw-mono flex items-center justify-between text-xs"><span>{b.key}</span><span className="tabular-nums text-muted-foreground">{b.count}</span></div>
            ))}
            {cop && cop.byApp.length === 0 && <div className="text-xs text-muted-foreground">Sin datos.</div>}
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="hw-mono flex items-center gap-2 text-sm"><Users className="h-4 w-4" /> TOP USUARIOS COPILOT</CardTitle></CardHeader>
          <CardContent className="space-y-1">
            {(cop?.topUsers ?? []).map((b) => (
              <div key={b.key} className="hw-mono flex items-center justify-between gap-2 text-xs"><span className="truncate">{b.key}</span><span className="tabular-nums text-muted-foreground">{b.count}</span></div>
            ))}
            {cop && cop.topUsers.length === 0 && <div className="text-xs text-muted-foreground">Sin datos.</div>}
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="hw-mono flex items-center gap-2 text-sm"><FileText className="h-4 w-4" /> RECURSOS TOCADOS (muestra)</CardTitle></CardHeader>
          <CardContent className="space-y-1">
            {(cop?.topResources ?? []).map((b, i) => (
              <div key={i} className="hw-mono flex items-center justify-between gap-2 text-xs"><span className="truncate" title={b.resource}>{b.resource}</span><span className="tabular-nums text-muted-foreground">{b.hits}</span></div>
            ))}
            {cop && cop.topResources.length === 0 && <div className="text-xs text-muted-foreground">Sin documentos en la muestra.</div>}
          </CardContent>
        </Card>
      </div>

      {/* Recientes */}
      <Card>
        <CardHeader><CardTitle className="hw-mono flex items-center gap-2 text-sm"><Activity className="h-4 w-4" /> INTERACCIONES RECIENTES DE COPILOT</CardTitle></CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <table className="w-full text-sm">
            <thead className="hw-mono text-[10px] uppercase text-muted-foreground">
              <tr className="border-b border-border"><th className="px-3 py-2 text-left">Hora</th><th className="px-3 py-2 text-left">Usuario</th><th className="px-3 py-2 text-left">App</th><th className="px-3 py-2 text-left">Documento/contexto</th></tr>
            </thead>
            <tbody>
              {(cop?.recent ?? []).map((d, i) => (
                <tr key={i} className={`border-b border-border/50 ${d.jailbreak ? 'bg-destructive/10' : ''}`}>
                  <td className="hw-mono px-3 py-1.5 text-xs text-muted-foreground">{fmt(d.time)}</td>
                  <td className="px-3 py-1.5">{d.user}{d.jailbreak && <ShieldAlert className="ml-1 inline h-3.5 w-3.5 text-destructive" />}</td>
                  <td className="px-3 py-1.5 text-muted-foreground">{d.app}</td>
                  <td className="px-3 py-1.5 text-xs text-muted-foreground"><span className="block max-w-md truncate" title={d.contexts.join(', ')}>{d.contexts.map((c) => c.split('/').pop()).join(', ') || '—'}</span></td>
                </tr>
              ))}
              {cop && cop.recent.length === 0 && <tr><td colSpan={4} className="px-3 py-4 text-center text-muted-foreground">Sin interacciones de Copilot en el periodo.</td></tr>}
            </tbody>
          </table>
        </CardContent>
      </Card>

      <p className="hw-mono flex items-center gap-1 text-[10px] text-muted-foreground"><ShieldCheck className="h-3 w-3" /> Visibilidad y detección — no bloquea. Fuente: SonicWall (SNI) + auditoría M365 (CopilotInteraction).</p>
    </div>
  );
}
