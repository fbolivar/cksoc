/**
 * Command Center SOC — panel-héroe estilo "security operations dashboard".
 * Resumen (amenazas/casos/vulns/estado), actividad de amenazas (tendencia por
 * severidad), reporte de vulnerabilidades (donut), alertas recientes, tráfico de
 * red (flujos), estado de dispositivos, incidentes resueltos vs creados y
 * actividad de usuarios (UEBA). Datos 100% reales con degradación elegante.
 */
import { useEffect, useMemo, useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import {
  ShieldAlert, CheckCircle2, Bug, Server, Gauge as GaugeIcon, ShieldCheck, TriangleAlert,
  Globe2, MonitorDot, Activity, ScanLine, ChevronRight, Radio, Zap,
} from 'lucide-react';
import { overviewApi, type OverviewData, type AlertTrend, type AssetRadar } from '@/lib/overview';
import { metricsApi, type SocMetrics } from '@/lib/metrics';
import { alertsApi, type AlertHit } from '@/lib/alerts';
import { uebaApi, type Anomaly, DETECTOR_ES } from '@/lib/ueba';
import { flowsApi, type FlowsOverview } from '@/lib/flows';
import { Card, CardContent } from '@/components/ui/card';

const TEAL = 'hsl(var(--primary))';
const RED = 'hsl(var(--destructive))';
const ORANGE = 'hsl(var(--warn-orange))';
const GREEN = 'hsl(var(--success))';
const CYAN = 'hsl(var(--cyan))';
const MUTE = 'hsl(var(--muted-foreground))';
const sevColor: Record<string, string> = { critica: RED, alta: ORANGE, media: TEAL, baja: GREEN };
const SEMA: Record<string, { label: string; color: string }> = {
  verde: { label: 'SEGURO', color: GREEN }, amarillo: { label: 'EN GESTIÓN', color: ORANGE }, rojo: { label: 'ATENCIÓN', color: RED },
};

/* ---------- KPI ---------- */
function Kpi({ icon: Icon, value, label, color, to }: { icon: typeof Server; value: string | number; label: string; color: string; to?: string }) {
  const inner = (
    <CardContent className="flex items-center gap-3 p-3">
      <div className="relative flex h-11 w-11 shrink-0 items-center justify-center rounded-full"
        style={{ background: `color-mix(in srgb, ${color} 14%, transparent)`, boxShadow: `0 0 14px color-mix(in srgb, ${color} 45%, transparent)`, border: `1px solid color-mix(in srgb, ${color} 40%, transparent)` }}>
        <Icon className="h-5 w-5" style={{ color }} />
      </div>
      <div className="min-w-0">
        <div className="hw-mono text-xl font-bold tabular-nums leading-none" style={{ color }}>{value}</div>
        <div className="hw-mono mt-1 truncate text-[9px] uppercase tracking-wide text-muted-foreground">{label}</div>
      </div>
      {to && <ChevronRight className="ml-auto h-4 w-4 text-muted-foreground" />}
    </CardContent>
  );
  return to ? <Card className="relative overflow-hidden transition-colors hover:border-primary/50"><Link to={to}>{inner}</Link></Card> : <Card className="relative overflow-hidden">{inner}</Card>;
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

/* ---------- Gráfico de área (tendencia por severidad) ---------- */
function AreaChart({ series, labels }: { series: { name: string; color: string; data: number[] }[]; labels: string[] }) {
  const W = 620, H = 190, pad = { l: 26, r: 8, t: 12, b: 20 };
  const n = Math.max(1, ...series.map((s) => s.data.length));
  const max = Math.max(1, ...series.flatMap((s) => s.data));
  const x = (i: number) => pad.l + (n <= 1 ? 0 : (i / (n - 1)) * (W - pad.l - pad.r));
  const y = (v: number) => pad.t + (1 - v / max) * (H - pad.t - pad.b);
  const path = (d: number[]) => d.map((v, i) => `${i === 0 ? 'M' : 'L'}${x(i).toFixed(1)} ${y(v).toFixed(1)}`).join(' ');
  const area = (d: number[]) => `${path(d)} L${x(d.length - 1).toFixed(1)} ${y(0)} L${x(0).toFixed(1)} ${y(0)} Z`;
  const ticks = [0, 0.5, 1].map((f) => Math.round(max * f));
  return (
    <div>
      <svg width="100%" viewBox={`0 0 ${W} ${H}`} style={{ maxHeight: 210 }}>
        {ticks.map((t, i) => (
          <g key={i}>
            <line x1={pad.l} x2={W - pad.r} y1={y(t)} y2={y(t)} stroke="hsl(var(--border))" strokeOpacity={0.3} />
            <text x={2} y={y(t) + 3} className="hw-mono" fill={MUTE} style={{ fontSize: 8 }}>{t}</text>
          </g>
        ))}
        {series.map((s) => (
          <g key={s.name}>
            <path d={area(s.data)} fill={s.color} opacity={0.1} />
            <path d={path(s.data)} fill="none" stroke={s.color} strokeWidth={1.8} style={{ filter: `drop-shadow(0 0 3px ${s.color})` }} />
          </g>
        ))}
        {labels.map((lb, i) => i % Math.ceil(n / 6) === 0 && (
          <text key={i} x={x(i)} y={H - 6} textAnchor="middle" className="hw-mono" fill={MUTE} style={{ fontSize: 8 }}>{lb}</text>
        ))}
      </svg>
      <div className="hw-mono mt-1 flex flex-wrap justify-center gap-3 text-[10px] text-muted-foreground">
        {series.map((s) => <span key={s.name} className="flex items-center gap-1"><span className="inline-block h-2 w-2 rounded-full" style={{ background: s.color }} /> {s.name}</span>)}
      </div>
    </div>
  );
}

/* ---------- Donut de vulnerabilidades ---------- */
function Donut({ segs, centerPct, centerLabel }: { segs: { label: string; value: number; color: string }[]; centerPct: number | null; centerLabel: string }) {
  const size = 150, stroke = 16, r = (size - stroke) / 2, C = 2 * Math.PI * r, cx = size / 2;
  const total = segs.reduce((a, b) => a + b.value, 0) || 1;
  let acc = 0;
  return (
    <div className="flex items-center gap-3">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="shrink-0">
        <circle cx={cx} cy={cx} r={r} fill="none" stroke="hsl(var(--border))" strokeOpacity={0.3} strokeWidth={stroke} />
        {segs.map((s, i) => {
          const frac = s.value / total; const dash = frac * C; const off = -acc * C; acc += frac;
          return <circle key={i} cx={cx} cy={cx} r={r} fill="none" stroke={s.color} strokeWidth={stroke}
            strokeDasharray={`${dash} ${C - dash}`} strokeDashoffset={off} transform={`rotate(-90 ${cx} ${cx})`} style={{ filter: `drop-shadow(0 0 3px ${s.color})` }} />;
        })}
        <text x={cx} y={cx - 2} textAnchor="middle" className="hw-mono" fill={RED} style={{ fontSize: 26, fontWeight: 700 }}>{centerPct != null ? `${centerPct}%` : '—'}</text>
        <text x={cx} y={cx + 16} textAnchor="middle" fill={MUTE} style={{ fontSize: 9 }}>{centerLabel}</text>
      </svg>
      <div className="space-y-1.5">
        {segs.map((s) => (
          <div key={s.label} className="flex items-center gap-2">
            <span className="inline-block h-2.5 w-2.5 rounded-sm" style={{ background: s.color, boxShadow: `0 0 5px ${s.color}` }} />
            <span className="hw-mono text-[11px] text-muted-foreground">{s.label}</span>
            <span className="hw-mono ml-auto text-sm font-bold tabular-nums" style={{ color: s.color }}>{s.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ---------- Barras agrupadas (resueltos vs creados) ---------- */
function GroupBars({ data }: { data: { label: string; resolved: number; created: number }[] }) {
  const max = Math.max(1, ...data.flatMap((d) => [d.resolved, d.created]));
  return (
    <div>
      <div className="flex h-28 items-end gap-1">
        {data.map((d, i) => (
          <div key={i} className="group flex flex-1 flex-col items-stretch justify-end" title={`${d.label}: ${d.resolved} resueltos, ${d.created} creados`}>
            <div className="flex items-end justify-center gap-0.5" style={{ height: '100%' }}>
              <div className="w-1.5 rounded-t" style={{ height: `${Math.max(2, (d.resolved / max) * 100)}%`, background: GREEN, boxShadow: `0 0 4px ${GREEN}` }} />
              <div className="w-1.5 rounded-t" style={{ height: `${Math.max(2, (d.created / max) * 100)}%`, background: RED, boxShadow: `0 0 4px ${RED}` }} />
            </div>
            <div className="hw-mono mt-1 truncate text-center text-[7px] text-muted-foreground">{d.label}</div>
          </div>
        ))}
      </div>
      <div className="hw-mono mt-1 flex justify-center gap-3 text-[10px] text-muted-foreground">
        <span className="flex items-center gap-1"><span className="inline-block h-2 w-2 rounded-sm" style={{ background: GREEN }} /> Resueltos</span>
        <span className="flex items-center gap-1"><span className="inline-block h-2 w-2 rounded-sm" style={{ background: RED }} /> Creados</span>
      </div>
    </div>
  );
}

/* ---------- Sparkline ---------- */
function Spark({ data, color = TEAL }: { data: number[]; color?: string }) {
  if (!data.length) return null;
  const W = 120, H = 28, max = Math.max(1, ...data);
  const pts = data.map((v, i) => `${(i / Math.max(1, data.length - 1)) * W},${H - (v / max) * H}`).join(' ');
  return <svg width={W} height={H} viewBox={`0 0 ${W} ${H}`}><polyline points={pts} fill="none" stroke={color} strokeWidth={1.5} /></svg>;
}

/* ---------- Mapa mundial de conexiones ---------- */
// Continentes aproximados (perímetros lon/lat) para contexto geográfico; los
// puntos de conexión se proyectan con la MISMA proyección equirectangular, así
// que quedan alineados aunque los contornos sean simplificados.
const CONTINENTS: [number, number][][] = [
  [[-165,60],[-168,66],[-155,71],[-128,70],[-100,72],[-82,73],[-62,60],[-52,47],[-66,45],[-70,41],[-75,35],[-81,25],[-97,16],[-106,20],[-114,28],[-124,40],[-125,48],[-135,57],[-150,59]],
  [[-78,8],[-60,10],[-50,0],[-35,-6],[-40,-20],[-55,-34],[-65,-42],[-72,-52],[-74,-48],[-71,-35],[-70,-20],[-76,-4],[-80,3]],
  [[-16,14],[-6,30],[10,32],[24,32],[32,31],[36,15],[44,11],[51,12],[42,-3],[40,-16],[33,-26],[20,-35],[14,-23],[9,2],[-8,4]],
  [[-10,43],[-4,50],[8,57],[28,64],[55,67],[90,72],[130,71],[160,67],[160,60],[142,52],[140,45],[130,34],[122,30],[120,22],[106,16],[100,7],[94,16],[80,8],[73,18],[60,24],[50,28],[43,13],[36,22],[30,30],[22,38],[12,44],[-6,36]],
  [[114,-20],[130,-12],[143,-11],[150,-24],[147,-38],[135,-37],[120,-34],[114,-28]],
];
const HOME: [number, number] = [-74.1, 4.7]; // Bogotá

function WorldMap({ conns, totalFlows }: { conns: { ip: string; flows: number; pais: string | null; lat: number | null; lon: number | null; ioc: boolean }[]; totalFlows: number }) {
  const W = 640, H = 320;
  const px = (lon: number) => ((lon + 180) / 360) * W;
  const py = (lat: number) => ((90 - lat) / 180) * H;
  const geo = conns.filter((c) => c.lat != null && c.lon != null).slice(0, 14);
  const maxF = Math.max(1, ...geo.map((c) => c.flows));
  const [hx, hy] = [px(HOME[0]), py(HOME[1])];
  const iocCount = geo.filter((c) => c.ioc).length;
  return (
    <div>
      <svg width="100%" viewBox={`0 0 ${W} ${H}`} style={{ maxHeight: 360 }}>
        <rect x={0} y={0} width={W} height={H} fill="hsl(var(--primary) / 0.02)" />
        {/* grácula */}
        {[-120, -60, 0, 60, 120].map((lon) => <line key={`m${lon}`} x1={px(lon)} y1={0} x2={px(lon)} y2={H} stroke="hsl(var(--border))" strokeOpacity={0.15} />)}
        {[-60, -30, 0, 30, 60].map((lat) => <line key={`p${lat}`} x1={0} y1={py(lat)} x2={W} y2={py(lat)} stroke="hsl(var(--border))" strokeOpacity={0.15} />)}
        {/* continentes */}
        {CONTINENTS.map((poly, i) => (
          <polygon key={i} points={poly.map(([lo, la]) => `${px(lo).toFixed(1)},${py(la).toFixed(1)}`).join(' ')}
            fill="hsl(var(--primary) / 0.10)" stroke="hsl(var(--primary) / 0.25)" strokeWidth={0.7} />
        ))}
        {/* arcos de conexión */}
        {geo.map((c, i) => {
          const x = px(c.lon!), y = py(c.lat!); const col = c.ioc ? RED : TEAL;
          const mx = (hx + x) / 2, my = (hy + y) / 2 - Math.hypot(x - hx, y - hy) * 0.28;
          return (
            <g key={i}>
              <path d={`M${hx} ${hy} Q${mx} ${my} ${x} ${y}`} fill="none" stroke={col} strokeWidth={1} strokeOpacity={0.55} strokeDasharray="4 5" className="cc-flow" style={{ filter: `drop-shadow(0 0 2px ${col})` }} />
              <circle cx={x} cy={y} r={3 + (c.flows / maxF) * 4} fill={col} fillOpacity={0.9} style={{ filter: `drop-shadow(0 0 5px ${col})` }}>
                <title>{`${c.ip}${c.pais ? ' · ' + c.pais : ''} · ${c.flows.toLocaleString('es-CO')} flujos${c.ioc ? ' · IOC' : ''}`}</title>
              </circle>
            </g>
          );
        })}
        {/* origen (Bogotá) */}
        <circle cx={hx} cy={hy} r={14} fill="none" stroke={GREEN} strokeWidth={1.2} className="cc-pulse" />
        <circle cx={hx} cy={hy} r={5} fill={GREEN} style={{ filter: `drop-shadow(0 0 6px ${GREEN})` }}><title>SOC · Bogotá (origen)</title></circle>
      </svg>
      <div className="hw-mono mt-1 flex flex-wrap items-center justify-center gap-4 text-[10px] text-muted-foreground">
        <span className="flex items-center gap-1"><span className="inline-block h-2 w-2 rounded-full" style={{ background: GREEN }} /> SOC Bogotá</span>
        <span className="flex items-center gap-1"><span className="inline-block h-2 w-2 rounded-full" style={{ background: TEAL }} /> destinos ({geo.length})</span>
        {iocCount > 0 && <span className="flex items-center gap-1"><span className="inline-block h-2 w-2 rounded-full" style={{ background: RED }} /> IOC ({iocCount})</span>}
        <span>{totalFlows.toLocaleString('es-CO')} flujos / 24h</span>
      </div>
    </div>
  );
}

function timeShort(ts: string): string { try { return new Date(ts).toLocaleTimeString('es-CO', { hour: '2-digit', minute: '2-digit' }); } catch { return ''; } }

export default function CommandCenter() {
  const [ov, setOv] = useState<OverviewData | null>(null);
  const [soc, setSoc] = useState<SocMetrics | null>(null);
  const [trend, setTrend] = useState<AlertTrend | null>(null);
  const [trendRange, setTrendRange] = useState<'7d' | '30d' | '90d'>('30d');
  const [barDays, setBarDays] = useState(30);
  const [bars, setBars] = useState<SocMetrics | null>(null);
  const [alerts, setAlerts] = useState<AlertHit[] | null>(null);
  const [anoms, setAnoms] = useState<Anomaly[] | null>(null);
  const [flows, setFlows] = useState<FlowsOverview | null>(null);
  const [radar, setRadar] = useState<AssetRadar | null>(null);
  const [clock, setClock] = useState(new Date());

  const loadCore = useCallback(async () => {
    const [o, m, a, u, f, r] = await Promise.allSettled([
      overviewApi.get(), metricsApi.soc(30),
      alertsApi.search({ range: '24h', triage: true, page: 1, size: 8 }),
      uebaApi.anomalies({ status: 'open' }), flowsApi.overview('24h'), overviewApi.radar(),
    ]);
    if (o.status === 'fulfilled') setOv(o.value);
    if (m.status === 'fulfilled') setSoc(m.value);
    if (a.status === 'fulfilled') setAlerts(a.value.items);
    if (u.status === 'fulfilled') setAnoms(u.value.anomalies);
    if (f.status === 'fulfilled') setFlows(f.value);
    if (r.status === 'fulfilled') setRadar(r.value);
  }, []);
  useEffect(() => { void loadCore(); const i = setInterval(() => void loadCore(), 30_000); return () => clearInterval(i); }, [loadCore]);
  useEffect(() => { overviewApi.trend(trendRange).then(setTrend).catch(() => undefined); }, [trendRange]);
  useEffect(() => { metricsApi.soc(barDays).then(setBars).catch(() => undefined); }, [barDays]);
  useEffect(() => { const i = setInterval(() => setClock(new Date()), 1000); return () => clearInterval(i); }, []);

  // --- derivados ---
  const sema = ov ? SEMA[ov.global.semaforo] : null;
  const vulnCrit = ov?.endpoints.vulnCriticas ?? 0;
  const vulnAlta = ov?.endpoints.vulnAltas ?? 0;
  const vulnTotal = ov?.endpoints.vulnTotal ?? 0;
  const vulnMedia = Math.max(0, vulnTotal - vulnCrit - vulnAlta);
  const highRiskPct = vulnTotal > 0 ? Math.round(((vulnCrit + vulnAlta) / vulnTotal) * 100) : null;
  const resueltos = soc ? soc.counts.resuelto + soc.counts.cerrado : null;
  const incOpen = soc ? soc.counts.abierto + soc.counts.en_curso : null;
  const risk = useMemo(() => {
    const crit = ov?.amenazas.criticas24h ?? 0; const breached = soc?.sla.overallPct != null ? 0 : 0;
    const siemPct = ov && ov.siem.total ? Math.round((ov.siem.ok / ov.siem.total) * 100) : 100;
    const anOpen = anoms?.length ?? 0;
    return Math.max(8, Math.min(100, Math.round(crit * 0.6 + (incOpen ?? 0) * 2 + anOpen * 3 + vulnCrit * 0.06 + (100 - siemPct) * 0.6 + breached)));
  }, [ov, soc, anoms, incOpen, vulnCrit]);

  const trendLabels = useMemo(() => {
    const n = trend?.critica.length ?? 0; const now = Date.now();
    const step = trendRange === '7d' ? 86400000 : trendRange === '30d' ? 86400000 : 86400000;
    return Array.from({ length: n }, (_, i) => { const d = new Date(now - (n - 1 - i) * step); return `${d.getDate()}/${d.getMonth() + 1}`; });
  }, [trend, trendRange]);

  const barData = useMemo(() => {
    const tp = bars?.throughput ?? soc?.throughput ?? [];
    return tp.slice(-24).map((p) => ({ label: p.date.slice(5), resolved: p.resolved, created: p.created }));
  }, [bars, soc]);

  const assets = (radar?.assets ?? []).slice().sort((a, b) => b.risk - a.risk).slice(0, 6);
  const assetChip = (band: string) => band === 'critico' || band === 'alto' ? { t: 'En riesgo', c: band === 'critico' ? RED : ORANGE } : band === 'medio' || band === 'monitoreado' ? { t: 'Monitoreado', c: TEAL } : { t: 'Seguro', c: GREEN };

  return (
    <div className="mx-auto max-w-[1400px] space-y-3">
      <style>{`
        @keyframes cc-dash { to { stroke-dashoffset: -36; } }
        .cc-flow { animation: cc-dash 1.1s linear infinite; }
        @keyframes cc-pz { 0%{ transform: scale(.7); opacity:.9 } 100%{ transform: scale(1.9); opacity:0 } }
        .cc-pulse { transform-box: fill-box; transform-origin: center; animation: cc-pz 1.6s ease-out infinite; }
      `}</style>
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-border/60 bg-card/60 px-4 py-2.5">
        <div className="flex items-center gap-3">
          <div className="relative flex h-9 w-9 items-center justify-center rounded-full" style={{ background: 'color-mix(in srgb, hsl(var(--primary)) 16%, transparent)', boxShadow: `0 0 16px color-mix(in srgb, ${TEAL} 55%, transparent)` }}>
            <Zap className="h-5 w-5" style={{ color: TEAL }} />
          </div>
          <div>
            <h1 className="hw-mono text-lg font-bold tracking-tight">CENTRO DE COMANDO · SOC</h1>
            <p className="hw-mono text-[10px] uppercase tracking-wide text-muted-foreground">HexWatch // Operaciones de seguridad en tiempo real</p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          {sema && <div className="hw-mono flex items-center gap-2 rounded-md border px-3 py-1.5 text-xs font-bold" style={{ borderColor: `color-mix(in srgb, ${sema.color} 50%, transparent)`, color: sema.color, boxShadow: `0 0 12px color-mix(in srgb, ${sema.color} 30%, transparent)` }}>
            <ShieldCheck className="h-4 w-4" /> {sema.label}
          </div>}
          <div className="text-right">
            <div className="hw-mono text-base font-bold tabular-nums" style={{ color: TEAL }}>{clock.toLocaleTimeString('es-CO', { hour12: false })}</div>
            <div className="hw-mono text-[10px] text-muted-foreground">{clock.toLocaleDateString('es-CO', { year: 'numeric', month: '2-digit', day: '2-digit' })}</div>
          </div>
        </div>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
        <Kpi icon={ShieldAlert} value={ov?.amenazas.criticas24h ?? '—'} label="Amenazas críticas 24h" color={RED} to="/alertas" />
        <Kpi icon={CheckCircle2} value={resueltos ?? '—'} label="Casos resueltos (30d)" color={GREEN} to="/incidentes" />
        <Kpi icon={Bug} value={vulnTotal || '—'} label="Vulnerabilidades" color={ORANGE} to="/vulnerabilidades" />
        <Kpi icon={Server} value={ov?.agentes.activos != null ? `${ov.agentes.activos}/${ov.agentes.total ?? '—'}` : '—'} label="Agentes activos" color={TEAL} to="/activos" />
        <Kpi icon={GaugeIcon} value={risk} label="Riesgo global" color={risk > 66 ? RED : risk > 40 ? ORANGE : GREEN} />
        <Kpi icon={TriangleAlert} value={incOpen ?? '—'} label="Incidentes abiertos" color={incOpen && incOpen > 0 ? ORANGE : GREEN} to="/incidentes" />
      </div>

      {/* Actividad de amenazas + Vulnerabilidades */}
      <div className="grid gap-3 lg:grid-cols-12">
        <div className="lg:col-span-8">
          <Panel title="Actividad de amenazas" icon={Activity} right={
            <div className="flex gap-1">{(['7d', '30d', '90d'] as const).map((r) => (
              <button key={r} onClick={() => setTrendRange(r)} className={`hw-mono rounded border px-2 py-0.5 text-[11px] ${trendRange === r ? 'border-primary text-primary' : 'border-border text-muted-foreground hover:text-foreground'}`}>{r}</button>
            ))}</div>}>
            {trend ? <AreaChart labels={trendLabels} series={[
              { name: 'Críticas', color: RED, data: trend.critica },
              { name: 'Altas', color: ORANGE, data: trend.alta },
              { name: 'Medias', color: CYAN, data: trend.media },
            ]} /> : <div className="flex h-48 items-center justify-center text-muted-foreground">Cargando…</div>}
          </Panel>
        </div>
        <div className="lg:col-span-4">
          <Panel title="Reporte de vulnerabilidades" icon={Bug} right={<Link to="/vulnerabilidades" className="hw-mono flex items-center gap-1 rounded bg-primary/15 px-2 py-0.5 text-[11px] text-primary hover:bg-primary/25"><ScanLine className="h-3.5 w-3.5" /> Escanear</Link>}>
            <Donut centerPct={highRiskPct} centerLabel="alto riesgo" segs={[
              { label: 'Críticas', value: vulnCrit, color: RED },
              { label: 'Altas', value: vulnAlta, color: ORANGE },
              { label: 'Medias', value: vulnMedia, color: TEAL },
            ]} />
          </Panel>
        </div>
      </div>

      {/* Mapa mundial de conexiones */}
      <Panel title="Mapa mundial de conexiones" icon={Globe2} right={flows && <span className="hw-mono text-[10px] text-muted-foreground">tráfico saliente geolocalizado · 24h</span>}>
        {flows ? <WorldMap conns={flows.topDst} totalFlows={flows.flows} /> : <div className="flex h-56 items-center justify-center text-muted-foreground">Cargando mapa…</div>}
      </Panel>

      {/* Alertas + Tráfico + Dispositivos */}
      <div className="grid gap-3 lg:grid-cols-3">
        <Panel title="Alertas recientes" icon={TriangleAlert} right={<Link to="/alertas" className="hw-mono text-[10px] text-muted-foreground hover:text-foreground">ver todas</Link>}>
          <div className="space-y-1.5">
            {(alerts ?? []).map((a) => (
              <Link key={a.id} to={`/alertas?agent=${encodeURIComponent(a.agent)}`} className="block rounded-md border border-border/60 bg-card/60 px-2 py-1.5 hover:border-primary/40" style={{ borderLeft: `3px solid ${sevColor[a.band] ?? TEAL}` }}>
                <div className="flex items-center gap-2">
                  <span className="hw-mono truncate text-[11px] font-medium text-foreground/90">{a.description}</span>
                  <span className="hw-mono ml-auto shrink-0 rounded px-1.5 py-0.5 text-[8px] font-bold uppercase" style={{ background: `color-mix(in srgb, ${sevColor[a.band]} 20%, transparent)`, color: sevColor[a.band] }}>{a.band}</span>
                </div>
                <div className="hw-mono mt-0.5 flex items-center gap-2 text-[9px] text-muted-foreground"><span>{timeShort(a.timestamp)}</span><span className="truncate">{a.agent}</span>{a.srcip && <span className="ml-auto">{a.srcip}</span>}</div>
              </Link>
            ))}
            {alerts && alerts.length === 0 && <div className="hw-mono flex items-center gap-2 py-4 text-[11px]" style={{ color: GREEN }}><CheckCircle2 className="h-4 w-4" /> Sin alertas de nivel alto en 24h.</div>}
            {alerts == null && <div className="hw-mono py-4 text-center text-[11px] text-muted-foreground">Cargando…</div>}
          </div>
        </Panel>

        <Panel title="Tráfico de red" icon={Globe2} right={flows && <span className="hw-mono text-[10px] text-muted-foreground">{flows.flows.toLocaleString('es-CO')} flujos/24h</span>}>
          {flows ? (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <div><div className="hw-mono text-[9px] uppercase text-muted-foreground">Flujos 24h</div><div className="hw-mono text-lg font-bold tabular-nums" style={{ color: TEAL }}>{flows.flows.toLocaleString('es-CO')}</div></div>
                <Spark data={flows.timeline.map((t) => t.flows)} color={TEAL} />
              </div>
              <div className="hw-mono text-[9px] uppercase text-muted-foreground">Top destinos externos</div>
              {flows.topDst.slice(0, 4).map((d, i) => (
                <div key={i} className="flex items-center gap-2 text-[10px]">
                  <span className="inline-block h-1.5 w-1.5 rounded-full" style={{ background: d.ioc ? RED : TEAL, boxShadow: `0 0 5px ${d.ioc ? RED : TEAL}` }} />
                  <span className="hw-mono truncate text-foreground/85">{d.ip}</span>
                  {d.pais && <span className="hw-mono text-muted-foreground">{d.pais}</span>}
                  {d.ioc && <span className="hw-mono rounded bg-destructive/15 px-1 text-[8px] font-bold text-destructive">IOC</span>}
                  <span className="hw-mono ml-auto tabular-nums text-muted-foreground">{d.flows.toLocaleString('es-CO')}</span>
                </div>
              ))}
            </div>
          ) : <div className="hw-mono py-6 text-center text-[11px] text-muted-foreground">Cargando…</div>}
        </Panel>

        <Panel title="Estado de dispositivos" icon={MonitorDot} right={<Link to="/activos" className="hw-mono text-[10px] text-muted-foreground hover:text-foreground">ver activos</Link>}>
          <div className="space-y-1.5">
            {assets.map((a) => { const ch = assetChip(a.band); return (
              <div key={a.name} className="flex items-center gap-2">
                <Server className="h-3.5 w-3.5 shrink-0" style={{ color: ch.c }} />
                <span className="hw-mono truncate text-[11px] text-foreground/90" title={a.ip}>{a.name}</span>
                <span className="hw-mono ml-auto shrink-0 rounded px-1.5 py-0.5 text-[9px] font-semibold" style={{ background: `color-mix(in srgb, ${ch.c} 18%, transparent)`, color: ch.c }}>{ch.t}</span>
              </div>
            ); })}
            {radar && assets.length === 0 && <div className="hw-mono py-4 text-center text-[11px] text-muted-foreground">Sin activos.</div>}
            {radar == null && <div className="hw-mono py-4 text-center text-[11px] text-muted-foreground">Cargando…</div>}
          </div>
        </Panel>
      </div>

      {/* Incidentes + Actividad de usuarios */}
      <div className="grid gap-3 lg:grid-cols-12">
        <div className="lg:col-span-7">
          <Panel title="Incidentes · resueltos vs creados" icon={CheckCircle2} right={
            <div className="flex gap-1">{([['7d', 7], ['30d', 30], ['90d', 90]] as const).map(([lb, dv]) => (
              <button key={dv} onClick={() => setBarDays(dv)} className={`hw-mono rounded border px-2 py-0.5 text-[11px] ${barDays === dv ? 'border-primary text-primary' : 'border-border text-muted-foreground hover:text-foreground'}`}>{lb}</button>
            ))}</div>}>
            {barData.length ? <GroupBars data={barData} /> : <div className="flex h-28 items-center justify-center text-muted-foreground">Sin datos de incidentes en la ventana.</div>}
            <div className="hw-mono mt-2 flex flex-wrap gap-x-4 gap-y-1 border-t border-border/50 pt-2 text-[10px] text-muted-foreground">
              <span>SLA cumplimiento: <b style={{ color: (soc?.sla.overallPct ?? 100) >= 90 ? GREEN : ORANGE }}>{soc?.sla.overallPct != null ? `${soc.sla.overallPct}%` : '—'}</b></span>
              <span>MTTR: <b className="text-foreground/80">{soc?.mttr.avgMinutes != null ? `${(soc.mttr.avgMinutes / 60).toFixed(1)} h` : '—'}</b></span>
              <span>Abiertos +24h: <b style={{ color: (soc?.aging.openOver24h ?? 0) > 0 ? ORANGE : GREEN }}>{soc?.aging.openOver24h ?? '—'}</b></span>
            </div>
          </Panel>
        </div>
        <div className="lg:col-span-5">
          <Panel title="Actividad de usuarios · UEBA" icon={Radio} right={<Link to="/comportamiento" className="hw-mono text-[10px] text-muted-foreground hover:text-foreground">ver UEBA</Link>}>
            <div className="max-h-44 space-y-1.5 overflow-y-auto pr-1">
              {(anoms ?? []).slice(0, 10).map((an) => (
                <div key={an.id} className="flex items-center gap-2">
                  <span className="inline-block h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: sevColor[an.severity] ?? TEAL, boxShadow: `0 0 5px ${sevColor[an.severity] ?? TEAL}` }} />
                  <span className="hw-mono truncate text-[11px] text-foreground/90">{an.entity}</span>
                  <span className="hw-mono truncate text-[9px] text-muted-foreground">{DETECTOR_ES[an.detector] ?? an.detector}</span>
                  <span className="hw-mono ml-auto shrink-0 text-[9px] text-muted-foreground">{timeShort(an.last_seen)}</span>
                </div>
              ))}
              {anoms && anoms.length === 0 && <div className="hw-mono flex items-center gap-2 py-4 text-[11px]" style={{ color: GREEN }}><CheckCircle2 className="h-4 w-4" /> Sin anomalías de comportamiento abiertas.</div>}
              {anoms == null && <div className="hw-mono py-4 text-center text-[11px] text-muted-foreground">Cargando…</div>}
            </div>
          </Panel>
        </div>
      </div>

      <p className="hw-mono flex items-center gap-1 text-[10px] text-muted-foreground"><Activity className="h-3 w-3" style={{ color: TEAL }} /> Datos en vivo · refresco 30s · fuentes: overview/incidentes/alertas/UEBA/flujos (SonicWall) · degradación elegante si una fuente no responde.</p>
    </div>
  );
}
