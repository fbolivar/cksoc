/**
 * NOC — Centro de Comando. Vista tipo "command center": KPIs con glow, medidor
 * radial de disponibilidad, topología de red en vivo (hub-and-spoke), recursos
 * SNMP, latencia/uptime por objetivo y tendencia de caídas. 100% datos reales
 * (nocApi.overview + report + trend). Identidad HexWatch (hw-mono, teal, oscuro).
 */
import { useEffect, useMemo, useState, useCallback } from 'react';
import {
  Activity, Server, CircleCheck, CircleX, Gauge as GaugeIcon, Radio, ShieldCheck,
  Cpu, MemoryStick, Cable, Wifi, Zap, TriangleAlert, Table as TableIcon,
} from 'lucide-react';
import { nocApi, type NocOverview, type NocReport, type NocTrend, type NocTarget } from '@/lib/noc';
import { Card, CardContent } from '@/components/ui/card';
import { Link } from 'react-router-dom';

const TEAL = 'hsl(var(--primary))';
const UP = 'hsl(152 65% 45%)';
const DOWN = 'hsl(var(--destructive))';
const AMBER = 'hsl(38 92% 50%)';
const MUTE = 'hsl(var(--muted-foreground))';

function shortName(n: string): string { return n.replace(/^SOC\s·\s/, '').replace(/^Internet\s/, '').replace(/\s\(.*\)$/, '').trim(); }
function upColor(p: number | null | undefined): string {
  if (p == null) return MUTE; if (p >= 99.9) return UP; if (p >= 99) return 'hsl(152 50% 55%)'; if (p >= 95) return AMBER; return DOWN;
}

/* ---------- Medidor radial ---------- */
function Gauge({ pct, size = 168, color, label, sub }: { pct: number | null; size?: number; color: string; label: string; sub?: string }) {
  const stroke = 12; const r = (size - stroke) / 2 - 2; const C = 2 * Math.PI * r; const v = Math.max(0, Math.min(100, pct ?? 0));
  const off = C * (1 - v / 100); const cx = size / 2;
  return (
    <div className="relative flex flex-col items-center">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle cx={cx} cy={cx} r={r} fill="none" stroke="hsl(var(--border))" strokeWidth={stroke} opacity={0.35} />
        <circle cx={cx} cy={cx} r={r} fill="none" stroke={color} strokeWidth={stroke} strokeLinecap="round"
          strokeDasharray={C} strokeDashoffset={off} transform={`rotate(-90 ${cx} ${cx})`}
          style={{ filter: `drop-shadow(0 0 6px ${color})`, transition: 'stroke-dashoffset .8s ease' }} />
        <text x={cx} y={cx - 2} textAnchor="middle" className="hw-mono" fill={color} style={{ fontSize: size * 0.24, fontWeight: 700 }}>{pct != null ? `${Math.round(v)}` : '—'}</text>
        <text x={cx} y={cx + size * 0.14} textAnchor="middle" fill={MUTE} style={{ fontSize: size * 0.08 }}>%</text>
      </svg>
      <div className="hw-mono mt-1 text-[11px] uppercase tracking-wide text-muted-foreground">{label}</div>
      {sub && <div className="hw-mono text-[10px] text-muted-foreground/70">{sub}</div>}
    </div>
  );
}

/* ---------- KPI con glow ---------- */
function Kpi({ icon: Icon, value, label, color }: { icon: typeof Server; value: string | number; label: string; color: string }) {
  return (
    <Card className="relative overflow-hidden">
      <CardContent className="flex items-center gap-3 p-3">
        <div className="relative flex h-11 w-11 shrink-0 items-center justify-center rounded-full"
          style={{ background: `color-mix(in srgb, ${color} 14%, transparent)`, boxShadow: `0 0 14px color-mix(in srgb, ${color} 45%, transparent)`, border: `1px solid color-mix(in srgb, ${color} 40%, transparent)` }}>
          <Icon className="h-5 w-5" style={{ color }} />
        </div>
        <div className="min-w-0">
          <div className="hw-mono text-xl font-bold tabular-nums leading-none" style={{ color }}>{value}</div>
          <div className="hw-mono mt-1 truncate text-[9px] uppercase tracking-wide text-muted-foreground">{label}</div>
        </div>
      </CardContent>
    </Card>
  );
}

/* ---------- Topología hub-and-spoke ---------- */
function Topology({ targets }: { targets: NocTarget[] }) {
  const W = 760, H = 430, cx = W / 2, cy = H / 2;
  const nodes = targets.filter((t) => t.enabled);
  const rx = 300, ry = 170;
  const placed = nodes.map((t, i) => {
    const a = (i / Math.max(1, nodes.length)) * Math.PI * 2 - Math.PI / 2;
    return { t, x: cx + rx * Math.cos(a), y: cy + ry * Math.sin(a), right: Math.cos(a) >= 0 };
  });
  const iconFor = (t: NocTarget) => {
    const g = (t.grupo || '').toLowerCase();
    if (g.includes('internet') || g.includes('enlace')) return Wifi;
    if (g.includes('perimetro') || g.includes('firewall')) return ShieldCheck;
    if (t.snmp_enabled) return Server;
    return Server;
  };
  return (
    <div className="relative">
      <svg width="100%" viewBox={`0 0 ${W} ${H}`} style={{ maxHeight: 440 }}>
        <defs>
          <radialGradient id="cc-core" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="hsl(var(--primary))" stopOpacity="0.9" />
            <stop offset="70%" stopColor="hsl(var(--primary))" stopOpacity="0.25" />
            <stop offset="100%" stopColor="hsl(var(--primary))" stopOpacity="0" />
          </radialGradient>
          <pattern id="cc-grid" width="38" height="38" patternUnits="userSpaceOnUse">
            <path d="M38 0H0V38" fill="none" stroke="hsl(var(--border))" strokeOpacity="0.18" strokeWidth="1" />
          </pattern>
        </defs>
        <rect x="0" y="0" width={W} height={H} fill="url(#cc-grid)" />
        {/* enlaces */}
        {placed.map(({ t, x, y }, i) => {
          const c = t.status === 'up' ? TEAL : t.status === 'down' ? DOWN : MUTE;
          return (
            <g key={`l${i}`}>
              <line x1={cx} y1={cy} x2={x} y2={y} stroke={c} strokeOpacity={0.5} strokeWidth={1.6}
                strokeDasharray="5 6" className="cc-flow" style={{ filter: `drop-shadow(0 0 3px ${c})` }} />
            </g>
          );
        })}
        {/* núcleo */}
        <circle cx={cx} cy={cy} r={66} fill="url(#cc-core)" />
        <circle cx={cx} cy={cy} r={34} fill="hsl(var(--card))" stroke={TEAL} strokeWidth={2} style={{ filter: `drop-shadow(0 0 10px ${TEAL})` }} />
        <path d={`M${cx - 6} ${cy - 13} L${cx + 7} ${cy - 2} L${cx - 1} ${cy - 1} L${cx + 6} ${cy + 13} L${cx - 7} ${cy + 1} L${cx + 1} ${cy} Z`} fill={TEAL} style={{ filter: `drop-shadow(0 0 4px ${TEAL})` }} />
        <text x={cx} y={cy + 52} textAnchor="middle" className="hw-mono" fill={TEAL} style={{ fontSize: 13, fontWeight: 700 }}>NOC</text>
        {/* nodos */}
        {placed.map(({ t, x, y, right }, i) => {
          const c = t.status === 'up' ? UP : t.status === 'down' ? DOWN : MUTE;
          const Icon = iconFor(t);
          return (
            <g key={`n${i}`}>
              {t.status === 'down' && <circle cx={x} cy={y} r={20} fill="none" stroke={DOWN} strokeWidth={1.5} className="cc-pulse" />}
              <circle cx={x} cy={y} r={15} fill="hsl(var(--card))" stroke={c} strokeWidth={2} style={{ filter: `drop-shadow(0 0 6px ${c})` }} />
              <foreignObject x={x - 8} y={y - 8} width={16} height={16}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 16 }}>
                  <Icon width={11} height={11} style={{ color: c }} />
                </div>
              </foreignObject>
              <text x={right ? x + 22 : x - 22} y={y - 1} textAnchor={right ? 'start' : 'end'} className="hw-mono" fill="hsl(var(--foreground))" style={{ fontSize: 11 }}>{shortName(t.name)}</text>
              <text x={right ? x + 22 : x - 22} y={y + 11} textAnchor={right ? 'start' : 'end'} className="hw-mono" fill={MUTE} style={{ fontSize: 9 }}>
                {t.status === 'up' ? (t.latency_ms != null ? `${t.latency_ms} ms` : 'OK') : t.status === 'down' ? 'CAÍDO' : 'off'}
              </text>
            </g>
          );
        })}
      </svg>
      <div className="hw-mono absolute right-2 top-2 flex items-center gap-1 text-[10px] text-muted-foreground">
        <span className="inline-block h-1.5 w-1.5 rounded-full" style={{ background: UP, boxShadow: `0 0 6px ${UP}` }} /> EN VIVO
      </div>
    </div>
  );
}

/* ---------- barras ---------- */
function BarsH({ rows }: { rows: { label: string; pct: number; color: string; val: string }[] }) {
  return (
    <div className="space-y-1.5">
      {rows.map((r, i) => (
        <div key={i} className="flex items-center gap-2">
          <div className="hw-mono w-28 shrink-0 truncate text-[10px] text-muted-foreground" title={r.label}>{r.label}</div>
          <div className="h-2 flex-1 overflow-hidden rounded-full bg-border/40">
            <div className="h-full rounded-full" style={{ width: `${Math.max(2, Math.min(100, r.pct))}%`, background: r.color, boxShadow: `0 0 6px ${r.color}` }} />
          </div>
          <div className="hw-mono w-14 shrink-0 text-right text-[10px] tabular-nums" style={{ color: r.color }}>{r.val}</div>
        </div>
      ))}
      {rows.length === 0 && <div className="hw-mono text-[10px] text-muted-foreground">Sin datos.</div>}
    </div>
  );
}
function BarsV({ points, color = TEAL }: { points: { label: string; v: number; max: number; tip?: string }[]; color?: string }) {
  const max = Math.max(1, ...points.map((p) => p.max));
  return (
    <div className="flex h-28 items-end gap-1">
      {points.map((p, i) => (
        <div key={i} className="group flex flex-1 flex-col items-center justify-end" title={p.tip ?? `${p.label}: ${p.v}`}>
          <div className="w-full rounded-t" style={{ height: `${Math.max(3, (p.v / max) * 100)}%`, background: p.v > 0 ? color : 'hsl(var(--border))', boxShadow: p.v > 0 ? `0 0 6px ${color}` : 'none', minHeight: 3 }} />
          <div className="hw-mono mt-1 w-full truncate text-center text-[8px] text-muted-foreground">{p.label}</div>
        </div>
      ))}
    </div>
  );
}

function Panel({ title, icon: Icon, children, right }: { title: string; icon: typeof Server; children: React.ReactNode; right?: React.ReactNode }) {
  return (
    <Card className="h-full">
      <div className="flex items-center justify-between border-b border-border/60 px-3 py-2">
        <div className="hw-mono flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wide text-foreground/90">
          <span style={{ color: TEAL }}>▸</span><Icon className="h-3.5 w-3.5" style={{ color: TEAL }} /> {title}
        </div>
        {right}
      </div>
      <CardContent className="p-3">{children}</CardContent>
    </Card>
  );
}

export default function NocCommand() {
  const [ov, setOv] = useState<NocOverview | null>(null);
  const [rep, setRep] = useState<NocReport | null>(null);
  const [trend, setTrend] = useState<NocTrend | null>(null);
  const [clock, setClock] = useState(new Date());

  const loadLive = useCallback(async () => { try { setOv(await nocApi.overview()); } catch { /* */ } }, []);
  const loadSlow = useCallback(async () => {
    try { const [r, t] = await Promise.all([nocApi.report(30), nocApi.trend(14)]); setRep(r); setTrend(t); } catch { /* */ }
  }, []);
  useEffect(() => { void loadLive(); void loadSlow(); const a = setInterval(() => void loadLive(), 15_000); const b = setInterval(() => void loadSlow(), 60_000); return () => { clearInterval(a); clearInterval(b); }; }, [loadLive, loadSlow]);
  useEffect(() => { const i = setInterval(() => setClock(new Date()), 1000); return () => clearInterval(i); }, []);

  const targets = useMemo(() => (ov?.grupos ?? []).flatMap((g) => g.targets), [ov]);
  const k = ov?.kpis;
  const dispPct = k && k.total > 0 ? Math.round((k.up / k.total) * 1000) / 10 : null;
  const snmp = targets.filter((t) => t.snmp_enabled && t.enabled);
  const down = targets.filter((t) => t.enabled && t.status === 'down');
  const latRows = targets.filter((t) => t.enabled && t.status === 'up' && t.latency_ms != null)
    .sort((a, b) => (b.latency_ms ?? 0) - (a.latency_ms ?? 0)).slice(0, 7)
    .map((t) => ({ label: shortName(t.name), v: t.latency_ms ?? 0, max: 1, tip: `${t.name}: ${t.latency_ms} ms` }));
  const upRows = (rep?.objetivos ?? []).slice(0, 8).map((o) => ({ label: shortName(o.name), pct: o.uptimePct, color: upColor(o.uptimePct), val: `${o.uptimePct.toFixed(2)}%` }));

  return (
    <div className="mx-auto max-w-[1400px] space-y-3">
      <style>{`
        @keyframes cc-dash { to { stroke-dashoffset: -44; } }
        .cc-flow { animation: cc-dash 1.1s linear infinite; }
        @keyframes cc-pz { 0%{ transform: scale(.8); opacity:.9 } 100%{ transform: scale(1.7); opacity:0 } }
        .cc-pulse { transform-box: fill-box; transform-origin: center; animation: cc-pz 1.4s ease-out infinite; }
      `}</style>

      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-border/60 bg-card/60 px-4 py-2.5">
        <div className="flex items-center gap-3">
          <div className="relative flex h-9 w-9 items-center justify-center rounded-full" style={{ background: 'color-mix(in srgb, hsl(var(--primary)) 16%, transparent)', boxShadow: `0 0 16px color-mix(in srgb, ${TEAL} 55%, transparent)` }}>
            <Zap className="h-5 w-5" style={{ color: TEAL }} />
          </div>
          <div>
            <h1 className="hw-mono text-lg font-bold tracking-tight">CENTRO DE COMANDO · NOC</h1>
            <p className="hw-mono text-[10px] uppercase tracking-wide text-muted-foreground">HexWatch // Monitoreo de disponibilidad en tiempo real</p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <div className="text-right">
            <div className="hw-mono text-base font-bold tabular-nums" style={{ color: TEAL }}>{clock.toLocaleTimeString('es-CO', { hour12: false })}</div>
            <div className="hw-mono text-[10px] text-muted-foreground">{clock.toLocaleDateString('es-CO', { year: 'numeric', month: '2-digit', day: '2-digit' })}{ov?.lastRun ? ` · últ. chequeo ${ov.lastRun.slice(11, 16)}` : ''}</div>
          </div>
          <Link to="/noc" className="hw-mono flex items-center gap-1 rounded border border-border px-2 py-1 text-[11px] text-muted-foreground hover:text-foreground"><TableIcon className="h-3.5 w-3.5" /> Tabla</Link>
        </div>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
        <Kpi icon={Server} value={k?.total ?? 0} label="Objetivos" color={TEAL} />
        <Kpi icon={CircleCheck} value={k?.up ?? 0} label="Activos" color={UP} />
        <Kpi icon={CircleX} value={k?.down ?? 0} label="Caídos" color={(k?.down ?? 0) > 0 ? DOWN : UP} />
        <Kpi icon={ShieldCheck} value={k?.avgUptime30 != null ? `${k.avgUptime30.toFixed(1)}%` : '—'} label="Uptime 30d" color={k?.avgUptime30 != null && k.avgUptime30 < 99 ? AMBER : UP} />
        <Kpi icon={GaugeIcon} value={k?.avgLatency != null ? `${k.avgLatency}ms` : '—'} label="Latencia prom" color={TEAL} />
        <Kpi icon={Radio} value={snmp.length} label="Equipos SNMP" color={TEAL} />
      </div>

      {/* Fila principal */}
      <div className="grid gap-3 lg:grid-cols-12">
        {/* Medidores */}
        <div className="lg:col-span-3">
          <Panel title="Disponibilidad" icon={GaugeIcon}>
            <div className="flex flex-col items-center gap-3">
              <Gauge pct={dispPct} color={dispPct != null && dispPct < 100 ? (dispPct < 80 ? DOWN : AMBER) : UP} label="Ahora" sub={`${k?.up ?? 0}/${k?.total ?? 0} operativos`} />
              <div className="h-px w-full bg-border/50" />
              <Gauge pct={k?.avgUptime30 ?? null} size={132} color={upColor(k?.avgUptime30)} label="Uptime 30 días" />
              <div className="flex w-full justify-around pt-1">
                <div className="text-center"><div className="hw-mono text-sm font-bold" style={{ color: UP }}>{k?.up ?? 0}</div><div className="hw-mono text-[9px] text-muted-foreground">UP</div></div>
                <div className="text-center"><div className="hw-mono text-sm font-bold" style={{ color: DOWN }}>{k?.down ?? 0}</div><div className="hw-mono text-[9px] text-muted-foreground">DOWN</div></div>
                <div className="text-center"><div className="hw-mono text-sm font-bold" style={{ color: MUTE }}>{k?.disabled ?? 0}</div><div className="hw-mono text-[9px] text-muted-foreground">OFF</div></div>
              </div>
            </div>
          </Panel>
        </div>

        {/* Topología */}
        <div className="lg:col-span-6">
          <Panel title="Topología de red" icon={Activity} right={<span className="hw-mono text-[10px] text-muted-foreground">{targets.filter((t) => t.enabled).length} nodos</span>}>
            {ov ? <Topology targets={targets} /> : <div className="flex h-72 items-center justify-center text-muted-foreground">Cargando…</div>}
          </Panel>
        </div>

        {/* Recursos + alertas */}
        <div className="lg:col-span-3 space-y-3">
          <Panel title="Recursos (SNMP)" icon={Cpu}>
            <div className="space-y-2.5">
              {snmp.map((t) => (
                <div key={t.id}>
                  <div className="hw-mono mb-1 flex items-center justify-between text-[10px]">
                    <span className="truncate text-foreground/90">{shortName(t.name)}</span>
                    {t.if_total != null && <span className="text-muted-foreground"><Cable className="mr-0.5 inline h-2.5 w-2.5" />{t.if_up ?? 0}/{t.if_total}</span>}
                  </div>
                  <div className="flex items-center gap-1.5">
                    <Cpu className="h-3 w-3" style={{ color: t.cpu_pct != null && t.cpu_pct >= 85 ? AMBER : TEAL }} />
                    <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-border/40"><div className="h-full rounded-full" style={{ width: `${t.cpu_pct ?? 0}%`, background: t.cpu_pct != null && t.cpu_pct >= 85 ? AMBER : TEAL }} /></div>
                    <span className="hw-mono w-8 text-right text-[9px] text-muted-foreground">{t.cpu_pct != null ? `${t.cpu_pct}%` : '—'}</span>
                  </div>
                  <div className="mt-1 flex items-center gap-1.5">
                    <MemoryStick className="h-3 w-3" style={{ color: t.mem_pct != null && t.mem_pct >= 90 ? AMBER : TEAL }} />
                    <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-border/40"><div className="h-full rounded-full" style={{ width: `${t.mem_pct ?? 0}%`, background: t.mem_pct != null && t.mem_pct >= 90 ? AMBER : TEAL }} /></div>
                    <span className="hw-mono w-8 text-right text-[9px] text-muted-foreground">{t.mem_pct != null ? `${t.mem_pct}%` : '—'}</span>
                  </div>
                </div>
              ))}
              {snmp.length === 0 && <div className="hw-mono text-[10px] text-muted-foreground">Sin equipos con SNMP.</div>}
            </div>
          </Panel>
          <Panel title="Alertas activas" icon={TriangleAlert}>
            {down.length === 0 ? (
              <div className="hw-mono flex items-center gap-2 text-[11px]" style={{ color: UP }}><CircleCheck className="h-4 w-4" /> Todo operativo</div>
            ) : (
              <div className="space-y-1">
                {down.map((t) => (
                  <div key={t.id} className="hw-mono flex items-center gap-2 rounded bg-destructive/10 px-2 py-1 text-[10px]">
                    <span className="inline-block h-2 w-2 rounded-full" style={{ background: DOWN, boxShadow: `0 0 6px ${DOWN}` }} />
                    <span className="truncate text-destructive">{t.name}</span>
                    <span className="ml-auto text-muted-foreground">{t.host}</span>
                  </div>
                ))}
              </div>
            )}
          </Panel>
        </div>
      </div>

      {/* Fila inferior: gráficos */}
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <Panel title="Latencia por objetivo" icon={GaugeIcon}>
          <BarsV points={latRows.length ? latRows : [{ label: '—', v: 0, max: 1 }]} color={TEAL} />
        </Panel>
        <Panel title="Uptime 30d por objetivo" icon={ShieldCheck}>
          <div className="max-h-28 overflow-y-auto pr-1"><BarsH rows={upRows} /></div>
        </Panel>
        <Panel title="Caídas por día (14d)" icon={TriangleAlert}>
          <BarsV points={(trend?.puntos ?? []).map((p) => ({ label: p.dia, v: p.caidas, max: 1, tip: `${p.dia}: ${p.caidas} caída(s), ${p.equipos} equipo(s)` }))} color={AMBER} />
        </Panel>
        <Panel title="Eventos recientes" icon={Activity}>
          <div className="max-h-28 space-y-1 overflow-y-auto pr-1">
            {(ov?.eventos ?? []).slice(0, 12).map((e, i) => (
              <div key={i} className="hw-mono flex items-center gap-1.5 text-[10px]">
                <span className="inline-block h-1.5 w-1.5 rounded-full" style={{ background: e.status === 'down' ? DOWN : UP }} />
                <span className="text-muted-foreground">{e.at.slice(5, 16).replace('T', ' ')}</span>
                <span style={{ color: e.status === 'down' ? DOWN : UP }}>{e.status === 'down' ? 'DOWN' : 'UP'}</span>
                <span className="truncate text-foreground/80">{shortName(e.name)}</span>
              </div>
            ))}
            {ov && ov.eventos.length === 0 && <div className="hw-mono text-[10px] text-muted-foreground">Sin eventos.</div>}
          </div>
        </Panel>
      </div>

      <p className="hw-mono flex items-center gap-1 text-[10px] text-muted-foreground"><Activity className="h-3 w-3" style={{ color: TEAL }} /> Datos en vivo · disponibilidad 15s · uptime/tendencia 60s · fuente NOC (chequeos activos + SNMP solo lectura).</p>
    </div>
  );
}
