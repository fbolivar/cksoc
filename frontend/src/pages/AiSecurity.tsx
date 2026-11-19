/**
 * Seguridad de IA — Inventario de IA (red + M365 Copilot), Monitoreo de Copilot,
 * Exfiltración a GenAI, Grafo de riesgo de IA y Postura OWASP Agentic / AIVSS.
 * Visibilidad + gobierno + detección (no bloquea).
 */
import { useEffect, useState, useCallback } from 'react';
import { AxiosError } from 'axios';
import {
  BrainCircuit, RefreshCw, Loader2, ShieldCheck, ShieldAlert, Cpu, Users, Activity, Bot, AlertTriangle,
  FileText, AppWindow, Clock, Upload, Network, Gauge, CircleCheck, CircleAlert, CircleX,
} from 'lucide-react';
import { aisecApi, type AiOverview, type RiskNode } from '@/lib/aisec';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

const RANGES = ['24h', '7d', '30d'] as const;
type Range = (typeof RANGES)[number];
const TABS = [
  { id: 'inv', label: 'Inventario', icon: Bot },
  { id: 'copilot', label: 'Copilot', icon: Activity },
  { id: 'agents', label: 'Agentes', icon: Cpu },
  { id: 'exfil', label: 'Exfiltración', icon: Upload },
  { id: 'risk', label: 'Riesgo', icon: Network },
  { id: 'posture', label: 'Postura', icon: Gauge },
] as const;
type Tab = (typeof TABS)[number]['id'];

function Kpi({ icon: Icon, label, value, tone }: { icon: typeof Cpu; label: string; value: number | string; tone?: 'danger' | 'warn' | 'ok' }) {
  const color = tone === 'danger' ? 'hsl(var(--destructive))' : tone === 'warn' ? 'hsl(38 92% 50%)' : tone === 'ok' ? 'hsl(152 65% 45%)' : 'hsl(var(--primary))';
  return (
    <Card><CardContent className="flex items-center gap-3 p-4">
      <Icon className="h-6 w-6" style={{ color }} />
      <div><div className="hw-mono text-2xl font-bold tabular-nums" style={{ color }}>{value}</div>
        <div className="hw-mono text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div></div>
    </CardContent></Card>
  );
}
function Pill({ ok, children }: { ok: boolean; children: React.ReactNode }) {
  return <span className="hw-mono inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide"
    style={{ background: ok ? 'hsl(152 60% 45% / .16)' : 'hsl(var(--destructive) / .16)', color: ok ? 'hsl(152 65% 55%)' : 'hsl(var(--destructive))' }}>{children}</span>;
}
function fmt(ts: string): string { return ts ? ts.slice(0, 16).replace('T', ' ') : '—'; }
function riskColor(s: number): string { return s >= 70 ? 'hsl(var(--destructive))' : s >= 40 ? 'hsl(38 92% 50%)' : 'hsl(152 65% 45%)'; }

export default function AiSecurity() {
  const [range, setRange] = useState<Range>('7d');
  const [tab, setTab] = useState<Tab>('inv');
  const [ov, setOv] = useState<AiOverview | null>(null);
  const [loading, setLoading] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  const reload = useCallback(async (r: Range) => {
    setLoading(true); setMsg(null);
    try { setOv(await aisecApi.overview(r)); }
    catch (e) { setMsg((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo cargar'); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { void reload(range); }, [range, reload]);

  const inv = ov?.inventory; const cop = ov?.copilot; const exfil = ov?.exfil; const risk = ov?.risk; const posture = ov?.posture;
  const k = inv?.kpis;

  return (
    <div className="mx-auto max-w-6xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="hw-mono flex items-center gap-2 text-2xl font-bold tracking-tight"><BrainCircuit className="h-6 w-6 text-primary" /> SEGURIDAD DE IA</h1>
          <p className="hw-mono text-[11px] tracking-wide text-muted-foreground">INVENTARIO // COPILOT // EXFILTRACIÓN // RIESGO // POSTURA OWASP-AGENTIC</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="hw-mono flex overflow-hidden rounded border border-border text-xs">
            {RANGES.map((r) => <button key={r} onClick={() => setRange(r)} className={`px-2.5 py-1 ${range === r ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:bg-muted'}`}>{r}</button>)}
          </div>
          <Button variant="outline" size="sm" onClick={() => reload(range)} disabled={loading}>{loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}</Button>
        </div>
      </div>

      {msg && <div className="hw-mono rounded border border-destructive/40 p-2 text-xs text-destructive">{msg}</div>}

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-6">
        <Kpi icon={Cpu} label="Servicios IA" value={k?.aiServices ?? 0} />
        <Kpi icon={ShieldAlert} label="Shadow" value={k?.shadowServices ?? 0} tone={k && k.shadowServices > 0 ? 'warn' : 'ok'} />
        <Kpi icon={Upload} label="Subido a IA (MB)" value={exfil?.totalSentMB ?? 0} tone={exfil && exfil.flagged > 0 ? 'danger' : undefined} />
        <Kpi icon={Activity} label="Interacc. Copilot" value={k?.copilotInteractions ?? 0} />
        <Kpi icon={AlertTriangle} label="Jailbreak" value={k?.jailbreakAttempts ?? 0} tone={k && k.jailbreakAttempts > 0 ? 'danger' : 'ok'} />
        <Kpi icon={Gauge} label="Postura IA" value={posture ? `${posture.score}` : '—'} tone={posture ? (posture.score >= 80 ? 'ok' : posture.score >= 60 ? 'warn' : 'danger') : undefined} />
      </div>

      {/* Tabs */}
      <div className="hw-mono flex flex-wrap gap-1 border-b border-border text-xs">
        {TABS.map((t) => (
          <button key={t.id} onClick={() => setTab(t.id)} className={`flex items-center gap-1.5 px-3 py-2 ${tab === t.id ? 'border-b-2 border-primary text-primary' : 'text-muted-foreground hover:text-foreground'}`}>
            <t.icon className="h-3.5 w-3.5" />{t.label}
          </button>
        ))}
      </div>

      {/* ---- INVENTARIO ---- */}
      {tab === 'inv' && (
        <div className="space-y-3">
          <Card>
            <CardHeader><CardTitle className="hw-mono flex items-center gap-2 text-sm"><Bot className="h-4 w-4" /> SERVICIOS DE IA · POR RED (SNI)</CardTitle></CardHeader>
            <CardContent className="overflow-x-auto p-0">
              <table className="w-full text-sm">
                <thead className="hw-mono text-[10px] uppercase text-muted-foreground"><tr className="border-b border-border">
                  <th className="px-3 py-2 text-left">Servicio</th><th className="px-3 py-2 text-left">Proveedor</th><th className="px-3 py-2 text-right">Equipos</th><th className="px-3 py-2 text-right">Hits</th><th className="px-3 py-2 text-center">Estado</th><th className="px-3 py-2 text-left">Último</th>
                </tr></thead>
                <tbody>
                  {(inv?.network ?? []).map((n) => (
                    <tr key={n.service} className="border-b border-border/50">
                      <td className="px-3 py-1.5 font-medium">{n.name}</td><td className="px-3 py-1.5 text-muted-foreground">{n.vendor}</td>
                      <td className="px-3 py-1.5 text-right tabular-nums">{n.devices}</td><td className="px-3 py-1.5 text-right tabular-nums">{n.hits}</td>
                      <td className="px-3 py-1.5 text-center"><Pill ok={n.sanctioned}>{n.sanctioned ? 'Aprobado' : 'Shadow'}</Pill></td>
                      <td className="hw-mono px-3 py-1.5 text-xs text-muted-foreground">{fmt(n.lastSeen)}</td>
                    </tr>
                  ))}
                  {inv?.copilot && inv.copilot.interactions > 0 && (
                    <tr className="border-b border-border/50 bg-primary/5">
                      <td className="px-3 py-1.5 font-medium">M365 Copilot <span className="text-[10px] text-muted-foreground">(identidad/O365)</span></td>
                      <td className="px-3 py-1.5 text-muted-foreground">Microsoft</td>
                      <td className="px-3 py-1.5 text-right tabular-nums">{inv.copilot.users}</td>
                      <td className="px-3 py-1.5 text-right tabular-nums">{inv.copilot.interactions}</td>
                      <td className="px-3 py-1.5 text-center"><Pill ok={inv.copilot.sanctioned}>{inv.copilot.sanctioned ? 'Aprobado' : 'Shadow'}</Pill></td>
                      <td className="hw-mono px-3 py-1.5 text-xs text-muted-foreground">{fmt(inv.copilot.lastSeen)}</td>
                    </tr>
                  )}
                  {inv && inv.network.length === 0 && (!inv.copilot || inv.copilot.interactions === 0) && <tr><td colSpan={6} className="px-3 py-4 text-center text-muted-foreground">Sin uso de IA en el periodo.</td></tr>}
                </tbody>
              </table>
              <p className="px-3 py-2 text-[11px] text-muted-foreground">La aprobación de cada servicio se gestiona en <b>Shadow-AI · Uso de IA</b> (política compartida).</p>
            </CardContent>
          </Card>
        </div>
      )}

      {/* ---- COPILOT ---- */}
      {tab === 'copilot' && cop && (
        <div className="space-y-3">
          {cop.jailbreakAttempts > 0 && (
            <Card className="border-destructive/50">
              <CardHeader><CardTitle className="hw-mono flex items-center gap-2 text-sm text-destructive"><AlertTriangle className="h-4 w-4" /> JAILBREAK / PROMPT-INJECTION ({cop.jailbreakAttempts})</CardTitle></CardHeader>
              <CardContent className="space-y-1">
                {cop.jailbreakList.map((j, i) => (
                  <div key={i} className="hw-mono flex flex-wrap items-center gap-x-3 text-xs"><span className="font-semibold text-destructive">{j.user}</span><span className="text-muted-foreground">{j.app}</span><span className="text-muted-foreground">{fmt(j.time)}</span></div>
                ))}
              </CardContent>
            </Card>
          )}
          {cop.xpiaAttempts > 0 && (
            <Card className="border-destructive/50">
              <CardHeader><CardTitle className="hw-mono flex items-center gap-2 text-sm text-destructive"><ShieldAlert className="h-4 w-4" /> INYECCIÓN INDIRECTA · XPIA ({cop.xpiaAttempts})</CardTitle></CardHeader>
              <CardContent className="space-y-1">
                <p className="text-[11px] text-muted-foreground">Contenido (documento/web citado) que intentó manipular al asistente — detección de Microsoft (XPIADetected).</p>
                {cop.xpiaList.map((j, i) => (
                  <div key={i} className="hw-mono flex flex-wrap items-center gap-x-3 text-xs"><span className="font-semibold text-destructive">{j.user}</span><span className="text-muted-foreground">{j.app}</span><span className="text-muted-foreground">{fmt(j.time)}</span></div>
                ))}
              </CardContent>
            </Card>
          )}
          <div className="grid gap-3 md:grid-cols-3">
            <Card><CardHeader><CardTitle className="hw-mono flex items-center gap-2 text-sm"><AppWindow className="h-4 w-4" /> POR APP</CardTitle></CardHeader>
              <CardContent className="space-y-1">{cop.byApp.map((b) => <div key={b.key} className="hw-mono flex justify-between text-xs"><span>{b.key}</span><span className="tabular-nums text-muted-foreground">{b.count}</span></div>)}{cop.byApp.length === 0 && <div className="text-xs text-muted-foreground">Sin datos.</div>}</CardContent></Card>
            <Card><CardHeader><CardTitle className="hw-mono flex items-center gap-2 text-sm"><Users className="h-4 w-4" /> TOP USUARIOS</CardTitle></CardHeader>
              <CardContent className="space-y-1">{cop.topUsers.map((b) => <div key={b.key} className="hw-mono flex justify-between gap-2 text-xs"><span className="truncate">{b.key}</span><span className="tabular-nums text-muted-foreground">{b.count}</span></div>)}</CardContent></Card>
            <Card><CardHeader><CardTitle className="hw-mono flex items-center gap-2 text-sm"><FileText className="h-4 w-4" /> DOCUMENTOS (muestra)</CardTitle></CardHeader>
              <CardContent className="space-y-1">{cop.topResources.map((b, i) => <div key={i} className="hw-mono flex justify-between gap-2 text-xs"><span className="truncate" title={b.resource}>{b.resource}</span><span className="tabular-nums text-muted-foreground">{b.hits}</span></div>)}{cop.topResources.length === 0 && <div className="text-xs text-muted-foreground">Sin documentos.</div>}</CardContent></Card>
          </div>
          {cop.topCitations.length > 0 && (
            <Card><CardHeader><CardTitle className="hw-mono flex items-center gap-2 text-sm"><AppWindow className="h-4 w-4" /> CITACIONES WEB EXTERNAS DE COPILOT ({cop.externalCitations})</CardTitle></CardHeader>
              <CardContent className="space-y-1">
                <p className="text-[11px] text-muted-foreground">Contenido externo que Copilot trajo a las respuestas (vector potencial de inyección indirecta).</p>
                {cop.topCitations.map((c, i) => (
                  <div key={i} className="hw-mono flex items-center justify-between gap-2 text-xs"><span className="truncate" title={c.url}>{c.url.replace(/^https?:\/\//, '')}</span><span className="tabular-nums text-muted-foreground">{c.hits}</span></div>
                ))}
              </CardContent></Card>
          )}
          <Card><CardHeader><CardTitle className="hw-mono flex items-center gap-2 text-sm"><Clock className="h-4 w-4" /> INTERACCIONES RECIENTES {cop.offHours > 0 && <span className="text-amber-500">· {cop.offHours} fuera de horario</span>}</CardTitle></CardHeader>
            <CardContent className="overflow-x-auto p-0"><table className="w-full text-sm">
              <thead className="hw-mono text-[10px] uppercase text-muted-foreground"><tr className="border-b border-border"><th className="px-3 py-2 text-left">Hora</th><th className="px-3 py-2 text-left">Usuario</th><th className="px-3 py-2 text-left">App / Agente</th><th className="px-3 py-2 text-left">Documento</th></tr></thead>
              <tbody>{cop.recent.map((d, i) => (
                <tr key={i} className={`border-b border-border/50 ${d.jailbreak || d.xpia ? 'bg-destructive/10' : ''}`}>
                  <td className="hw-mono px-3 py-1.5 text-xs text-muted-foreground">{fmt(d.time)}</td>
                  <td className="px-3 py-1.5">{d.user}{d.jailbreak && <ShieldAlert className="ml-1 inline h-3.5 w-3.5 text-destructive" />}{d.xpia && <AlertTriangle className="ml-1 inline h-3.5 w-3.5 text-destructive" />}</td>
                  <td className="px-3 py-1.5 text-muted-foreground">{d.app}{d.agent && <span className="ml-1 rounded bg-primary/10 px-1 text-[10px] text-primary">{d.agent}</span>}</td>
                  <td className="px-3 py-1.5 text-xs text-muted-foreground"><span className="block max-w-md truncate">{d.contexts.map((c) => c.split(/[\\/]/).pop()).join(', ') || '—'}</span></td>
                </tr>))}</tbody>
            </table></CardContent></Card>
        </div>
      )}

      {/* ---- AGENTES (A4) ---- */}
      {tab === 'agents' && cop && (
        <Card>
          <CardHeader><CardTitle className="hw-mono flex items-center gap-2 text-sm"><Cpu className="h-4 w-4" /> AGENTES DE IA EN EL TENANT ({cop.agents.length})</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            <p className="text-[11px] text-muted-foreground">Agentes declarativos / Copilot Studio detectados en la auditoría de M365 (AppIdentity), distintos del Copilot estándar.</p>
            <table className="w-full text-sm">
              <thead className="hw-mono text-[10px] uppercase text-muted-foreground"><tr className="border-b border-border"><th className="px-3 py-2 text-left">Agente</th><th className="px-3 py-2 text-left">Tipo</th><th className="px-3 py-2 text-right">Interacciones</th></tr></thead>
              <tbody>{cop.agents.map((a) => (
                <tr key={a.id} className="border-b border-border/50">
                  <td className="px-3 py-1.5 font-medium">{a.label}</td>
                  <td className="px-3 py-1.5"><Pill ok={a.builtin}>{a.builtin ? 'Integrado (Microsoft)' : 'Personalizado'}</Pill></td>
                  <td className="px-3 py-1.5 text-right tabular-nums">{a.interactions}</td>
                </tr>))}
                {cop.agents.length === 0 && <tr><td colSpan={3} className="px-3 py-4 text-center text-muted-foreground">No se detectaron agentes de IA propios en el periodo (solo Copilot estándar).</td></tr>}
              </tbody>
            </table>
            <p className="text-[11px] text-muted-foreground">Un agente <b>Personalizado</b> (Copilot Studio) merece revisión: qué datos toca y quién lo usa. Se marcan también en "Interacciones recientes" de Copilot.</p>
          </CardContent>
        </Card>
      )}

      {/* ---- EXFILTRACIÓN ---- */}
      {tab === 'exfil' && exfil && (
        <Card>
          <CardHeader><CardTitle className="hw-mono flex items-center gap-2 text-sm"><Upload className="h-4 w-4" /> EXFILTRACIÓN A GenAI · BYTES SUBIDOS (umbral {exfil.thresholdMB} MB)</CardTitle></CardHeader>
          <CardContent className="overflow-x-auto p-0">
            <table className="w-full text-sm">
              <thead className="hw-mono text-[10px] uppercase text-muted-foreground"><tr className="border-b border-border"><th className="px-3 py-2 text-left">Equipo</th><th className="px-3 py-2 text-left">Servicio</th><th className="px-3 py-2 text-right">Subido MB</th><th className="px-3 py-2 text-right">Bajado MB</th><th className="px-3 py-2 text-center">Estado</th><th className="px-3 py-2 text-left">Último</th></tr></thead>
              <tbody>{exfil.rows.map((r, i) => (
                <tr key={i} className={`border-b border-border/50 ${r.flagged ? 'bg-destructive/10' : ''}`}>
                  <td className="px-3 py-1.5 font-medium">{r.host ?? r.srcip}{r.host && <span className="ml-1 text-[10px] text-muted-foreground">{r.srcip}</span>}</td>
                  <td className="px-3 py-1.5">{r.name} {!r.sanctioned && <ShieldAlert className="inline h-3 w-3 text-amber-500" />}</td>
                  <td className="px-3 py-1.5 text-right font-bold tabular-nums" style={{ color: r.flagged ? 'hsl(var(--destructive))' : undefined }}>{r.sentMB}</td>
                  <td className="px-3 py-1.5 text-right tabular-nums text-muted-foreground">{r.rcvdMB}</td>
                  <td className="px-3 py-1.5 text-center">{r.flagged ? <Pill ok={false}>Revisar</Pill> : <span className="text-[10px] text-muted-foreground">ok</span>}</td>
                  <td className="hw-mono px-3 py-1.5 text-xs text-muted-foreground">{fmt(r.lastSeen)}</td>
                </tr>))}
                {exfil.rows.length === 0 && <tr><td colSpan={6} className="px-3 py-4 text-center text-muted-foreground">Sin subidas a servicios de IA (o el firewall no reporta bytes).</td></tr>}
              </tbody>
            </table>
            <p className="px-3 py-2 text-[11px] text-muted-foreground">Señal basada en volumen subido (data.sentbyte del SonicWall). Umbral configurable (AISEC_EXFIL_MB).</p>
          </CardContent>
        </Card>
      )}

      {/* ---- RIESGO + GRAFO ---- */}
      {tab === 'risk' && risk && (
        <div className="space-y-3">
          <Card><CardHeader><CardTitle className="hw-mono flex items-center gap-2 text-sm"><Network className="h-4 w-4" /> GRAFO DE RIESGO DE IA</CardTitle></CardHeader>
            <CardContent><RiskGraph nodes={risk.graph.nodes} edges={risk.graph.edges} /></CardContent></Card>
          <Card><CardHeader><CardTitle className="hw-mono flex items-center gap-2 text-sm"><AlertTriangle className="h-4 w-4" /> ENTIDADES POR RIESGO</CardTitle></CardHeader>
            <CardContent className="space-y-2">
              {risk.entities.map((e) => (
                <div key={e.id} className="space-y-1">
                  <div className="flex items-center justify-between gap-2 text-sm">
                    <span className="truncate font-medium">{e.kind === 'user' ? '👤' : '💻'} {e.label}</span>
                    <span className="hw-mono tabular-nums font-bold" style={{ color: riskColor(e.score) }}>{e.score}</span>
                  </div>
                  <div className="h-1.5 w-full overflow-hidden rounded bg-muted"><div className="h-full rounded" style={{ width: `${e.score}%`, background: riskColor(e.score) }} /></div>
                  {e.reasons.length > 0 && <div className="hw-mono text-[11px] text-muted-foreground">{e.reasons.join(' · ')}</div>}
                </div>
              ))}
              {risk.entities.length === 0 && <div className="text-xs text-muted-foreground">Sin entidades con riesgo de IA en el periodo.</div>}
              <p className="pt-1 text-[11px] text-muted-foreground">↔ Estas entidades también aparecen en el <b>grafo XDR</b>: pivotea un usuario o IP y verás su uso de IA junto al resto de la actividad.</p>
            </CardContent></Card>
        </div>
      )}

      {/* ---- POSTURA ---- */}
      {tab === 'posture' && posture && (
        <div className="space-y-3">
          <Card><CardContent className="flex items-center gap-4 p-5">
            <div className="hw-mono text-4xl font-bold tabular-nums" style={{ color: posture.score >= 80 ? 'hsl(152 65% 45%)' : posture.score >= 60 ? 'hsl(38 92% 50%)' : 'hsl(var(--destructive))' }}>{posture.score}</div>
            <div><div className="hw-mono text-sm font-semibold">PUNTAJE DE POSTURA DE IA</div><div className="text-xs text-muted-foreground">Alineado a OWASP Top 10 for Agentic AI · severidad estilo AIVSS</div></div>
          </CardContent></Card>
          {posture.items.map((it) => {
            const Icon = it.status === 'ok' ? CircleCheck : it.status === 'warn' ? CircleAlert : CircleX;
            const color = it.status === 'ok' ? 'hsl(152 65% 45%)' : it.status === 'warn' ? 'hsl(38 92% 50%)' : 'hsl(var(--destructive))';
            return (
              <Card key={it.id}><CardContent className="flex gap-3 p-4">
                <Icon className="mt-0.5 h-5 w-5 shrink-0" style={{ color }} />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-semibold">{it.category}</span>
                    <span className="hw-mono rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">{it.owasp}</span>
                    <span className="hw-mono text-[10px] text-muted-foreground">AIVSS {it.severity.toFixed(1)}</span>
                    {it.evidence > 0 && <span className="hw-mono text-[10px]" style={{ color }}>· {it.evidence} evidencia(s)</span>}
                  </div>
                  <div className="mt-0.5 text-sm text-muted-foreground">{it.finding}</div>
                  <div className="mt-0.5 text-[11px] text-muted-foreground">↳ {it.recommendation}</div>
                </div>
              </CardContent></Card>
            );
          })}
        </div>
      )}

      <p className="hw-mono flex items-center gap-1 text-[10px] text-muted-foreground"><ShieldCheck className="h-3 w-3" /> Visibilidad y detección — no bloquea. Fuente: SonicWall (SNI/bytes) + auditoría M365 (Copilot).</p>
    </div>
  );
}

/** Grafo bipartito compacto: entidades (izq) ↔ servicios/recursos (der). */
function RiskGraph({ nodes, edges }: { nodes: RiskNode[]; edges: { from: string; to: string; weight: number; shadow?: boolean }[] }) {
  const left = nodes.filter((n) => n.type === 'user' || n.type === 'device').slice(0, 8);
  const right = nodes.filter((n) => n.type === 'service' || n.type === 'resource').slice(0, 10);
  if (left.length === 0 && right.length === 0) return <div className="text-xs text-muted-foreground">Sin datos para el grafo.</div>;
  const rowH = 34, padY = 20, W = 720;
  const H = Math.max(left.length, right.length) * rowH + padY * 2;
  const lx = 150, rx = W - 170;
  const posL = (i: number) => padY + i * rowH + rowH / 2;
  const posR = (i: number) => padY + i * rowH + rowH / 2;
  const idxL = new Map(left.map((n, i) => [n.id, i])); const idxR = new Map(right.map((n, i) => [n.id, i]));
  const col = (s: number) => (s >= 70 ? 'hsl(0 72% 51%)' : s >= 40 ? 'hsl(38 92% 50%)' : 'hsl(152 55% 45%)');
  return (
    <div className="overflow-x-auto">
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ minWidth: 520, maxHeight: 420 }}>
        {edges.map((e, i) => {
          const li = idxL.get(e.from), ri = idxR.get(e.to); if (li == null || ri == null) return null;
          return <line key={i} x1={lx} y1={posL(li)} x2={rx} y2={posR(ri)} stroke={e.shadow ? 'hsl(0 72% 51% / .5)' : 'hsl(var(--muted-foreground) / .3)'} strokeWidth={Math.min(3, 1 + Math.log10((e.weight || 1) + 1))} />;
        })}
        {left.map((n, i) => (
          <g key={n.id}>
            <circle cx={lx} cy={posL(i)} r={6} fill={col(n.risk)} />
            <text x={lx - 12} y={posL(i) + 3} textAnchor="end" className="hw-mono" fontSize="10" fill="currentColor">{n.label.length > 22 ? n.label.slice(0, 21) + '…' : n.label}</text>
          </g>
        ))}
        {right.map((n, i) => (
          <g key={n.id}>
            <rect x={rx} y={posR(i) - 6} width={12} height={12} rx={2} fill={n.type === 'service' ? 'hsl(217 91% 60%)' : 'hsl(262 83% 66%)'} />
            <text x={rx + 18} y={posR(i) + 3} className="hw-mono" fontSize="10" fill="currentColor">{n.label.length > 24 ? n.label.slice(0, 23) + '…' : n.label}</text>
          </g>
        ))}
      </svg>
      <div className="hw-mono mt-1 flex gap-4 text-[10px] text-muted-foreground">
        <span>● entidad (color = riesgo)</span><span style={{ color: 'hsl(217 91% 60%)' }}>■ servicio IA</span><span style={{ color: 'hsl(262 83% 66%)' }}>■ documento</span>
      </div>
    </div>
  );
}
