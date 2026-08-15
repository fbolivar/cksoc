/**
 * Command Center — panel-héroe del rediseño "HexWatch Tactical" (HUD).
 * Radar de activos, gauge de riesgo global, feed en vivo, mapa de sedes,
 * acciones rápidas y tendencia de seguridad. Datos reales (overview/incidentes/
 * UEBA) con degradación elegante si algún endpoint no responde.
 */
import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { overviewApi, type RadarAsset, type RiskBand, type SedeMetrics } from '@/lib/overview';
import { incidentsApi } from '@/lib/incidents';
import { uebaApi } from '@/lib/ueba';

type Col = 'primary' | 'destructive' | 'success' | 'warn-orange' | 'cyan';
const cssVar = (n: string) => getComputedStyle(document.documentElement).getPropertyValue('--' + n).trim();
const C = (n: string, a?: number) => { const v = cssVar(n); return a == null ? `hsl(${v})` : `hsl(${v} / ${a})`; };

interface KpiData {
  alertas24h: number; criticas: number; agActivos: number; agTotal: number;
  siemPct: number; vulnCrit: number; incOpen: number; incBreached: number; slaPct: number | null; uebaOpen: number;
  risk: number;
}
const FALLBACK: KpiData = { alertas24h: 10000, criticas: 158, agActivos: 21, agTotal: 23, siemPct: 98, vulnCrit: 210, incOpen: 1, incBreached: 1, slaPct: 100, uebaOpen: 4, risk: 63 };

const FEED = [
  ['destructive', '100210', 'Borrado en repositorio protegido GVM', 'PRIN-WINSRV01'],
  ['warn-orange', '5710', 'SSH: intento con usuario inexistente', '45.134.26.9'],
  ['destructive', '100002', 'UEBA: 79 fallos de auth · Julian Martinez', 'GVMCORP'],
  ['primary', '550', 'FIM: cambio de checksum en /etc', 'gvm-soc-app'],
  ['warn-orange', '100210', 'Borrado en repositorio protegido', 'GVMBOGLOG01'],
  ['cyan', '31530', 'Múltiples conexiones bloqueadas (FortiGate)', 'FW-GVM'],
] as const;
const SEDES: [string, number, number][] = [['Bogotá', .30, .55], ['Medellín', .26, .44], ['La Ceja', .28, .50], ['Entrerríos', .24, .40], ['Fómeque', .33, .58]];
const SEDE_INFO: { name: string; region: string; rol?: string }[] = [
  { name: 'Bogotá', region: 'Cundinamarca', rol: 'Principal' },
  { name: 'Medellín', region: 'Antioquia' },
  { name: 'La Ceja', region: 'Antioquia' },
  { name: 'Entrerríos', region: 'Antioquia' },
  { name: 'Fómeque', region: 'Cundinamarca' },
];

export default function CommandCenter() {
  const [d, setD] = useState<KpiData>(FALLBACK);
  const [clock, setClock] = useState('');
  const [feed, setFeed] = useState<number[]>([0, 1, 2, 3, 4, 5]);
  const [range, setRange] = useState<'24h' | '7d' | '30d' | '90d'>('7d');
  const [filter, setFilter] = useState<'all' | 'ep' | 'srv' | 'net'>('all');

  const [radarData, setRadarData] = useState<{ total: number; assets: RadarAsset[] }>({ total: 0, assets: [] });
  const [sedes, setSedes] = useState<SedeMetrics[] | null>(null);
  const navigate = useNavigate();

  const riskRef = useRef(FALLBACK.risk);
  const filterRef = useRef(filter); filterRef.current = filter;
  const rangeRef = useRef(range); rangeRef.current = range;
  const navRef = useRef(navigate); navRef.current = navigate;
  const assetsRef = useRef<RadarAsset[]>([]);
  const totalRef = useRef(0);
  const doPlaceRef = useRef<() => void>(() => {});

  // --- datos reales ---
  useEffect(() => {
    let alive = true;
    (async () => {
      const [ov, mx, ue] = await Promise.allSettled([overviewApi.get(), incidentsApi.metrics(), uebaApi.anomalies({ status: 'open' })]);
      if (!alive) return;
      const nd: KpiData = { ...FALLBACK };
      if (ov.status === 'fulfilled') { const o = ov.value; nd.alertas24h = o.amenazas.alertas24h; nd.criticas = o.amenazas.criticas24h; nd.agActivos = o.agentes.activos; nd.agTotal = o.agentes.total; nd.siemPct = o.siem.total ? Math.round(o.siem.ok / o.siem.total * 100) : nd.siemPct; nd.vulnCrit = o.endpoints.vulnCriticas; }
      if (mx.status === 'fulfilled') { const m = mx.value; nd.incOpen = m.counts.abierto + m.counts.en_curso; nd.incBreached = m.sla.openBreached; nd.slaPct = m.sla.compliancePct; }
      if (ue.status === 'fulfilled') nd.uebaOpen = ue.value.anomalies.length;
      nd.risk = Math.max(8, Math.min(100, Math.round(nd.criticas * 0.16 + nd.incBreached * 16 + nd.uebaOpen * 3 + nd.vulnCrit * 0.04 + (100 - nd.siemPct) * 0.6)));
      riskRef.current = nd.risk;
      setD(nd);
    })();
    overviewApi.radar().then((r) => { if (alive) setRadarData(r); }).catch(() => undefined);
    overviewApi.sedes().then((r) => { if (alive) setSedes(r); }).catch(() => undefined);
    return () => { alive = false; };
  }, []);

  // Cuando llegan los activos, recolocar los puntos del radar y redibujar.
  useEffect(() => {
    assetsRef.current = radarData.assets;
    totalRef.current = radarData.total;
    doPlaceRef.current();
  }, [radarData]);

  // reloj + feed en vivo
  useEffect(() => {
    const t = setInterval(() => setClock(new Date().toLocaleTimeString('es-CO', { hour: '2-digit', minute: '2-digit', second: '2-digit' })), 1000);
    setClock(new Date().toLocaleTimeString('es-CO', { hour: '2-digit', minute: '2-digit', second: '2-digit' }));
    const reduce = matchMedia('(prefers-reduced-motion:reduce)').matches;
    let n = 6;
    const f = reduce ? null : setInterval(() => { setFeed((prev) => [n++ % FEED.length, ...prev].slice(0, 7)); }, 3400);
    return () => { clearInterval(t); if (f) clearInterval(f); };
  }, []);

  // --- canvases ---
  const bgRef = useRef<HTMLCanvasElement>(null);
  const radarRef = useRef<HTMLCanvasElement>(null);
  const gaugeRef = useRef<HTMLCanvasElement>(null);
  const mapRef = useRef<HTMLCanvasElement>(null);
  const offRef = useRef<HTMLCanvasElement>(null);
  const trendRef = useRef<HTMLCanvasElement>(null);
  const tipRef = useRef<HTMLDivElement>(null);
  const radarTipRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const reduce = matchMedia('(prefers-reduced-motion:reduce)').matches;
    let raf = 0, t = 0, gauge = 0;
    const dpr = (cvs: HTMLCanvasElement) => { const r = cvs.getBoundingClientRect(); const p = window.devicePixelRatio || 1; cvs.width = Math.max(1, r.width * p); cvs.height = Math.max(1, r.height * p); const c = cvs.getContext('2d')!; c.setTransform(p, 0, 0, p, 0, 0); return { c, w: r.width, h: r.height }; };
    const seed = (s: number) => () => { s = (s * 9301 + 49297) % 233280; return s / 233280; };

    // --- radar de activos REALES: un punto por agente, colocado por su riesgo ---
    interface Placed { ang: number; rf: number; size: number; band: RiskBand; asset: RadarAsset }
    let placed: Placed[] = [];
    const hash = (s: string, salt: number) => { let h = salt >>> 0; for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0; return (h % 10000) / 10000; };
    const CAT_BASE: Record<string, number> = { ep: Math.PI * 0.5, srv: Math.PI * (7 / 6), net: Math.PI * (11 / 6) };
    const bandCol: Record<RiskBand, Col> = { critico: 'destructive', alto: 'warn-orange', medio: 'primary', monitoreado: 'cyan', sano: 'success' };
    const placeDots = () => {
      placed = assetsRef.current.map((a) => {
        const h1 = hash(a.name, 7), h2 = hash(a.name, 99);
        const ang = (CAT_BASE[a.category] ?? 0) + (h1 - 0.5) * 1.7;
        let rf = 0.12 + (1 - a.risk / 100) * 0.8 + (h2 - 0.5) * 0.05;
        rf = Math.max(0.11, Math.min(0.96, rf));
        const size = a.risk >= 70 ? 5 : a.risk >= 45 ? 4 : a.risk >= 25 ? 3.2 : a.risk >= 10 ? 2.6 : 2.2;
        return { ang, rf, size, band: a.band, asset: a };
      });
      radar();
    };
    doPlaceRef.current = placeDots;

    // trend data
    let trendData: number[][] = [];
    const genTrend = (rg: string) => { const pts = ({ '24h': 24, '7d': 28, '30d': 30, '90d': 45 } as Record<string, number>)[rg]; const rr = seed(({ '24h': 11, '7d': 22, '30d': 33, '90d': 44 } as Record<string, number>)[rg]); const s = [[], [], []] as number[][]; const base = [9, 20, 42]; for (let i = 0; i < pts; i++) for (let k = 0; k < 3; k++) { const v = base[k] + Math.sin(i / 3 + k) * base[k] * .4 + (rr() - .5) * base[k] * .7; s[k].push(Math.max(0, v)); } return s; };
    let lastRange = '';

    const drawBg = () => { const cvs = bgRef.current; if (!cvs) return; const { c, w, h } = dpr(cvs); c.clearRect(0, 0, w, h); const step = 40; c.strokeStyle = C('foreground', .04); c.lineWidth = 1; for (let x = 0; x < w; x += step) { c.beginPath(); c.moveTo(x, 0); c.lineTo(x, h); c.stroke(); } for (let y = 0; y < h; y += step) { c.beginPath(); c.moveTo(0, y); c.lineTo(w, y); c.stroke(); } };

    const radar = () => {
      const cvs = radarRef.current; if (!cvs) return; const { c, w, h } = dpr(cvs); const cx = w / 2, cy = h / 2, R = Math.min(w, h) / 2 - 10; c.clearRect(0, 0, w, h);
      for (let i = 1; i <= 5; i++) { const rr = R * i / 5; c.beginPath(); for (let a = 0; a <= 6; a++) { const an = Math.PI / 6 + a * Math.PI / 3, x = cx + Math.cos(an) * rr, y = cy + Math.sin(an) * rr; if (a) c.lineTo(x, y); else c.moveTo(x, y); } c.closePath(); c.strokeStyle = C('foreground', .1); c.lineWidth = 1; c.stroke(); }
      c.strokeStyle = C('foreground', .06); for (let s = 0; s < 6; s++) { const an = Math.PI / 6 + s * Math.PI / 3; c.beginPath(); c.moveTo(cx, cy); c.lineTo(cx + Math.cos(an) * R, cy + Math.sin(an) * R); c.stroke(); }
      const cg = (c as CanvasRenderingContext2D & { createConicGradient?: (a: number, x: number, y: number) => CanvasGradient }).createConicGradient;
      if (cg) { const g = cg.call(c, t, cx, cy); g.addColorStop(0, C('primary', .2)); g.addColorStop(.1, C('primary', 0)); g.addColorStop(1, C('primary', 0)); c.beginPath(); c.arc(cx, cy, R, 0, 7); c.fillStyle = g; c.fill(); }
      c.beginPath(); c.moveTo(cx, cy); c.lineTo(cx + Math.cos(t) * R, cy + Math.sin(t) * R); c.strokeStyle = C('primary', .5); c.lineWidth = 1.5; c.stroke();
      placed.forEach((p) => {
        if (filterRef.current !== 'all' && p.asset.category !== filterRef.current) return;
        const col = bandCol[p.band]; const high = p.band === 'critico' || p.band === 'alto';
        const pulse = high ? (1 + Math.sin(t * 3 + p.ang * 5) * 0.3) : 1; const sz = p.size * pulse;
        const x = cx + Math.cos(p.ang) * R * p.rf, y = cy + Math.sin(p.ang) * R * p.rf;
        c.beginPath(); c.arc(x, y, sz * 2.2, 0, 7); c.fillStyle = C(col, .12); c.fill();
        c.beginPath(); c.arc(x, y, sz, 0, 7); c.fillStyle = C(col); c.shadowBlur = high ? 10 : 0; c.shadowColor = C(col); c.fill(); c.shadowBlur = 0;
        if (p.band === 'critico') { const b = sz + 4; c.strokeStyle = C(col, .85); c.lineWidth = 1; ([[-1, -1], [1, -1], [1, 1], [-1, 1]] as number[][]).forEach((q) => { c.beginPath(); c.moveTo(x + q[0] * b, y + q[1] * b - q[1] * 3); c.lineTo(x + q[0] * b, y + q[1] * b); c.lineTo(x + q[0] * b - q[0] * 3, y + q[1] * b); c.stroke(); }); }
      });
      c.beginPath(); for (let a = 0; a <= 6; a++) { const an = Math.PI / 6 + a * Math.PI / 3, rr = R * .13, x = cx + Math.cos(an) * rr, y = cy + Math.sin(an) * rr; if (a) c.lineTo(x, y); else c.moveTo(x, y); } c.closePath(); c.fillStyle = C('card', .9); c.fill(); c.strokeStyle = C('primary', .6); c.lineWidth = 1.5; c.stroke();
      c.fillStyle = C('foreground'); c.textAlign = 'center'; c.textBaseline = 'middle'; c.font = `800 ${R * .085}px ${cssVar('--hw-mono')}`; c.fillText(String(totalRef.current || placed.length), cx, cy - R * .02); c.font = `600 ${R * .032}px ${cssVar('--hw-mono')}`; c.fillStyle = C('muted-foreground'); c.fillText('ACTIVOS', cx, cy + R * .05);
    };

    const drawGauge = () => { const cvs = gaugeRef.current; if (!cvs) return; const { c, w, h } = dpr(cvs); const cx = w / 2, cy = h / 2, R = Math.min(w, h) / 2 - 8; c.clearRect(0, 0, w, h); const start = Math.PI * .75, end = Math.PI * 2.25, val = gauge / 100; c.beginPath(); c.arc(cx, cy, R, start, end); c.strokeStyle = C('foreground', .08); c.lineWidth = 9; c.lineCap = 'round'; c.stroke(); const col: Col = gauge > 66 ? 'destructive' : gauge > 40 ? 'warn-orange' : 'success'; c.beginPath(); c.arc(cx, cy, R, start, start + (end - start) * val); c.strokeStyle = C(col); c.lineWidth = 9; c.lineCap = 'round'; c.shadowBlur = 14; c.shadowColor = C(col); c.stroke(); c.shadowBlur = 0; for (let k = 0; k <= 10; k++) { const an = start + (end - start) * k / 10; c.beginPath(); c.moveTo(cx + Math.cos(an) * (R - 13), cy + Math.sin(an) * (R - 13)); c.lineTo(cx + Math.cos(an) * (R - 18), cy + Math.sin(an) * (R - 18)); c.strokeStyle = C('foreground', .18); c.lineWidth = 1.5; c.stroke(); } c.fillStyle = C('foreground'); c.textAlign = 'center'; c.textBaseline = 'middle'; c.font = `800 ${R * .42}px ${cssVar('--hw-mono')}`; c.fillText(String(Math.round(gauge)), cx, cy); };

    const drawMap = () => { const cvs = mapRef.current; if (!cvs) return; const { c, w, h } = dpr(cvs); c.clearRect(0, 0, w, h); const step = 15; c.fillStyle = C('foreground', .12); for (let x = step; x < w; x += step) for (let y = step; y < h; y += step) { const nx = x / w, ny = y / h; const inMass = (nx > .14 && nx < .44 && ny > .2 && ny < .9) || (nx > .44 && nx < .62 && ny > .15 && ny < .55) || (nx > .6 && nx < .9 && ny > .2 && ny < .7); if (inMass) { c.beginPath(); c.arc(x, y, 1.1, 0, 7); c.fill(); } } const hub = [SEDES[0][1] * w, SEDES[0][2] * h]; SEDES.slice(1).forEach((s) => { const p = [s[1] * w, s[2] * h], mx = (hub[0] + p[0]) / 2, my = Math.min(hub[1], p[1]) - 40; c.beginPath(); c.moveTo(hub[0], hub[1]); c.quadraticCurveTo(mx, my, p[0], p[1]); c.strokeStyle = C('primary', .4); c.lineWidth = 1.2; c.stroke(); }); };

    const drawOffline = () => { const cvs = offRef.current; if (!cvs) return; const { c, w, h } = dpr(cvs); c.clearRect(0, 0, w, h); const data = [22, 31, 18, 26, 40, 55, 168], max = 180, bw = w / data.length * .5, gap = w / data.length; const labels = ['-6', '-5', '-4', '-3', '-2', 'ayer', 'hoy']; data.forEach((v, i) => { const bh = v / max * (h - 18), x = i * gap + gap / 2 - bw / 2, y = h - bh - 14, last = i === data.length - 1; c.fillStyle = last ? C('destructive') : C('primary', .5); if (last) { c.shadowBlur = 12; c.shadowColor = C('destructive'); } c.fillRect(x, y, bw, bh); c.shadowBlur = 0; c.fillStyle = C('muted-foreground'); c.font = `600 9px ${cssVar('--hw-mono')}`; c.textAlign = 'center'; c.fillText(labels[i], x + bw / 2, h - 2); }); };

    const drawTrend = () => { const cvs = trendRef.current; if (!cvs) return; const { c, w, h } = dpr(cvs); if (lastRange !== rangeRef.current) { trendData = genTrend(rangeRef.current); lastRange = rangeRef.current; } c.clearRect(0, 0, w, h); const pad = 8, n = trendData[0].length; let maxV = 0; trendData.forEach((s) => s.forEach((v) => { if (v > maxV) maxV = v; })); maxV *= 1.15; c.strokeStyle = C('foreground', .06); for (let gy = 0; gy <= 4; gy++) { const y = pad + (h - 2 * pad) * gy / 4; c.beginPath(); c.moveTo(0, y); c.lineTo(w, y); c.stroke(); } const cols: Col[] = ['destructive', 'warn-orange', 'primary']; for (let k = 2; k >= 0; k--) { const s = trendData[k]; c.beginPath(); s.forEach((v, i) => { const x = i / (n - 1) * w, y = pad + (h - 2 * pad) * (1 - v / maxV); if (i) c.lineTo(x, y); else c.moveTo(x, y); }); const g = c.createLinearGradient(0, 0, 0, h); g.addColorStop(0, C(cols[k], .22)); g.addColorStop(1, C(cols[k], 0)); c.lineTo(w, h); c.lineTo(0, h); c.closePath(); c.fillStyle = g; c.fill(); c.beginPath(); s.forEach((v, i) => { const x = i / (n - 1) * w, y = pad + (h - 2 * pad) * (1 - v / maxV); if (i) c.lineTo(x, y); else c.moveTo(x, y); }); c.strokeStyle = C(cols[k]); c.lineWidth = 2; c.lineJoin = 'round'; c.shadowBlur = 8; c.shadowColor = C(cols[k], .5); c.stroke(); c.shadowBlur = 0; } (cvs as HTMLCanvasElement & { _m?: { n: number; w: number } })._m = { n, w }; };

    const renderStatic = () => { drawBg(); drawGauge(); drawMap(); drawOffline(); drawTrend(); };
    renderStatic();

    // animación gauge → target
    let g0: number | null = null; const gTarget = () => riskRef.current;
    const animGauge = (ts: number) => { if (g0 == null) g0 = ts; const p = Math.min((ts - g0) / 1300, 1), e = 1 - Math.pow(1 - p, 3); gauge = gTarget() * e; drawGauge(); if (p < 1) requestAnimationFrame(animGauge); };
    requestAnimationFrame(animGauge);

    const loop = () => { t += 0.014; radar(); drawBg(); raf = requestAnimationFrame(loop); };
    if (reduce) radar(); else raf = requestAnimationFrame(loop);

    // trend hover
    const cvs = trendRef.current, tip = tipRef.current;
    const onMove = (e: MouseEvent) => { const m = (cvs as HTMLCanvasElement & { _m?: { n: number; w: number } })._m; if (!m || !tip || !cvs) return; const rect = cvs.getBoundingClientRect(), mx = e.clientX - rect.left, i = Math.max(0, Math.min(m.n - 1, Math.round(mx / m.w * (m.n - 1)))); const L = ['Críticas', 'Altas', 'Medias'], cc: Col[] = ['destructive', 'warn-orange', 'primary']; let html = `<div>PUNTO ${i + 1}</div>`; [0, 1, 2].forEach((k) => { html += `<div class="r"><i style="background:${C(cc[k])}"></i>${L[k]}: <b>${Math.round(trendData[k][i])}</b></div>`; }); tip.innerHTML = html; tip.style.opacity = '1'; const x = i / (m.n - 1) * rect.width; tip.style.left = Math.min(rect.width - 140, Math.max(0, x - 60)) + 'px'; tip.style.top = '6px'; };
    const onLeave = () => { if (tip) tip.style.opacity = '0'; };
    cvs?.addEventListener('mousemove', onMove); cvs?.addEventListener('mouseleave', onLeave);

    // radar: hover + clic sobre activos reales
    const rcvs = radarRef.current, rtip = radarTipRef.current;
    const CATLBL: Record<string, string> = { ep: 'Endpoint', srv: 'Servidor', net: 'Red' };
    const hitAt = (e: MouseEvent): Placed | null => {
      if (!rcvs) return null; const rect = rcvs.getBoundingClientRect(); const cx = rect.width / 2, cy = rect.height / 2, R = Math.min(rect.width, rect.height) / 2 - 10;
      const mx = e.clientX - rect.left, my = e.clientY - rect.top; let best: Placed | null = null, bd = 11;
      for (const p of placed) { if (filterRef.current !== 'all' && p.asset.category !== filterRef.current) continue; const x = cx + Math.cos(p.ang) * R * p.rf, y = cy + Math.sin(p.ang) * R * p.rf; const dd = Math.hypot(mx - x, my - y); if (dd < bd) { bd = dd; best = p; } }
      return best;
    };
    const rMove = (e: MouseEvent) => {
      if (!rcvs || !rtip) return; const p = hitAt(e);
      if (!p) { rtip.style.opacity = '0'; rcvs.style.cursor = 'default'; return; }
      const a = p.asset, rect = rcvs.getBoundingClientRect();
      rtip.innerHTML = `<div style="font-weight:700">${a.name}</div><div class="r">${CATLBL[a.category]} · ${a.status === 'active' ? 'activo' : 'desconectado'}</div><div class="r"><i style="background:${C(bandCol[p.band])}"></i>riesgo ${a.risk} · ${a.band}</div><div class="r">${a.criticalVulns} vulns críticas · ${a.alerts24h} alertas 24h</div>`;
      rtip.style.opacity = '1'; rcvs.style.cursor = 'pointer';
      rtip.style.left = Math.min(rect.width - 175, Math.max(0, e.clientX - rect.left + 12)) + 'px';
      rtip.style.top = Math.max(0, e.clientY - rect.top + 12) + 'px';
    };
    const rLeave = () => { if (rtip) rtip.style.opacity = '0'; if (rcvs) rcvs.style.cursor = 'default'; };
    const rClick = (e: MouseEvent) => { const p = hitAt(e); if (p) navRef.current(`/alertas?agent=${encodeURIComponent(p.asset.name)}`); };
    rcvs?.addEventListener('mousemove', rMove); rcvs?.addEventListener('mouseleave', rLeave); rcvs?.addEventListener('click', rClick);

    const onResize = () => { renderStatic(); radar(); };
    let rt: number; const rl = () => { clearTimeout(rt); rt = window.setTimeout(onResize, 150); };
    window.addEventListener('resize', rl);
    const obs = new MutationObserver(() => { renderStatic(); }); obs.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });

    return () => { cancelAnimationFrame(raf); cvs?.removeEventListener('mousemove', onMove); cvs?.removeEventListener('mouseleave', onLeave); rcvs?.removeEventListener('mousemove', rMove); rcvs?.removeEventListener('mouseleave', rLeave); rcvs?.removeEventListener('click', rClick); window.removeEventListener('resize', rl); obs.disconnect(); };
  }, []);

  const fmt = (n: number) => n.toLocaleString('es-CO');
  const relTime = (iso: string | null): string => {
    if (!iso) return '';
    const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
    if (s < 3600) return `hace ${Math.round(s / 60)} min`;
    if (s < 86400) return `hace ${Math.round(s / 3600)} h`;
    return `hace ${Math.round(s / 86400)} d`;
  };
  const sedeList: SedeMetrics[] = sedes ?? SEDE_INFO.map((s) => ({ ...s, agentes: 0, agentesActivos: 0, logins7d: 0, usuarios: 0, ultimaActividad: null, estado: 'activa' as const }));
  const sedesActivas = sedeList.filter((s) => s.estado === 'activa').length;

  return (
    <div className="relative mx-auto max-w-[1480px]">
      <canvas ref={bgRef} className="pointer-events-none absolute inset-0 -z-10 h-full w-full opacity-70" />
      <div className="flex flex-col gap-4">
        {/* ticker */}
        <div className="hw-ticker hw-reveal">
          <span className="t"><i style={{ background: 'hsl(var(--success))', boxShadow: '0 0 6px hsl(var(--success))' }} />SISTEMA <b className="hw-blink">OPERATIVO</b></span>
          <span className="t">INGESTA <b>1.2k</b> ev/min</span>
          <span className="t">INDEXER <b>245GB</b> · 5%</span>
          <span className="t">AGENTES <b>{d.agActivos}/{d.agTotal}</b></span>
          <span className="t"><i style={{ background: 'hsl(var(--destructive))', boxShadow: '0 0 6px hsl(var(--destructive))' }} />{d.incBreached} SLA <b style={{ color: 'hsl(var(--destructive))' }}>VENCIDO</b></span>
          <span className="t">KEV <b style={{ color: 'hsl(var(--success))' }}>0 activas</b></span>
        </div>

        {/* head */}
        <div className="hw-reveal flex flex-wrap items-end justify-between gap-3" style={{ animationDelay: '.03s' }}>
          <div>
            <h1 className="m-0 text-2xl font-bold tracking-tight">COMMAND <span style={{ color: 'hsl(var(--primary))', textShadow: '0 0 16px hsl(var(--primary)/.5)' }}>CENTER</span></h1>
            <p className="hw-mono mt-1 text-[11px] tracking-wide text-muted-foreground">GVM CORPORATION // POSTURA EN TIEMPO REAL // {clock}</p>
          </div>
        </div>

        {/* KPIs */}
        <div className="hw-reveal grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6" style={{ animationDelay: '.06s' }}>
          <div className="hud hw-kpi"><div className="l"><Ico d="M4 6h16M4 12h16M4 18h10" /> Alertas 24h</div><div className="v">{fmt(d.alertas24h)}</div><div className="d hw-up">▲ 6% VS AYER</div></div>
          <div className="hud hw-kpi crit"><div className="l"><Ico d="M12 3l9 16H3z" /> Críticas</div><div className="v">{fmt(d.criticas)}</div><div className="d hw-up">▲ 12 NUEVAS</div></div>
          <div className="hud hw-kpi"><div className="l"><Ico d="M4 7h16v13H4z" /> Incidentes</div><div className="v">{d.incOpen}</div><div className="d hw-up">{d.incBreached} SLA VENCIDO</div></div>
          <div className="hud hw-kpi"><div className="l"><Ico d="M12 2 4 5v6c0 5 3.5 8 8 10 4.5-2 8-5 8-10V5z" /> UEBA</div><div className="v">{d.uebaOpen}</div><div className="d hw-flat">HOST NUEVO · FALLOS</div></div>
          <div className="hud hw-kpi"><div className="l"><Ico d="M12 2 4 5v6c0 5 3.5 8 8 10 4.5-2 8-5 8-10V5z" /> Agentes</div><div className="v">{d.agActivos}<span className="text-sm text-muted-foreground">/{d.agTotal}</span></div><div className="d hw-up">▼ {d.agTotal - d.agActivos} OFFLINE</div></div>
          <div className="hud hw-kpi"><div className="l"><Ico d="M12 8v4l3 2" circle /> SLA</div><div className="v hw-down">{d.slaPct != null ? d.slaPct + '%' : '—'}</div><div className="d hw-down">✓ CASOS EN PLAZO</div></div>
        </div>

        {/* radar + risk/feed */}
        <div className="grid gap-4 lg:grid-cols-[1.5fr_1fr]">
          <div className="hud hw-reveal" style={{ animationDelay: '.1s' }}>
            <div className="hw-chdr"><h3>Threat Radar</h3><span className="sub">activos en un vistazo</span><div className="flex-1" />
              <div className="flex flex-wrap gap-1">{(['all', 'ep', 'srv', 'net'] as const).map((f) => <button key={f} className={`hw-chip ${filter === f ? 'on' : ''}`} onClick={() => setFilter(f)}>{{ all: 'Todos', ep: 'Endpoints', srv: 'Servidores', net: 'Red' }[f]}</button>)}</div>
            </div>
            <div className="relative grid min-h-[360px] place-items-center">
              <canvas ref={radarRef} className="block aspect-square w-full max-w-[460px]" style={{ filter: 'drop-shadow(0 0 20px hsl(var(--primary)/.12))' }} />
              <div id="hw-ttip" ref={radarTipRef} className="hw-clip" style={{ maxWidth: 175 }} />
            </div>
            <div className="hw-legend mt-2">
              {([['destructive', 'Crítico'], ['warn-orange', 'Alto'], ['primary', 'Medio'], ['cyan', 'Monitoreado'], ['success', 'Sano']] as [string, string][]).map((l) => <span key={l[1]}><i style={{ background: `hsl(var(--${l[0]}))` }} />{l[1]}</span>)}
            </div>
          </div>

          <div className="flex flex-col gap-4">
            <div className="hud hw-reveal" style={{ animationDelay: '.14s' }}>
              <div className="hw-chdr"><h3>Riesgo global</h3><span className="sub">índice compuesto</span></div>
              <div className="flex items-center gap-4">
                <canvas ref={gaugeRef} className="h-[104px] w-[104px] flex-none" style={{ filter: 'drop-shadow(0 0 12px hsl(var(--primary)/.25))' }} />
                <div>
                  <div className="text-[32px] font-extrabold leading-none tracking-tight">{d.risk}</div>
                  <div className="hw-tag mt-1">nivel: <span style={{ color: d.risk > 66 ? 'hsl(var(--destructive))' : 'hsl(var(--warn-orange))' }}>{d.risk > 66 ? 'crítico' : d.risk > 40 ? 'elevado' : 'bajo'}</span></div>
                  <div className="hw-mono mt-2 text-[11px]" style={{ color: 'hsl(var(--warn-orange))' }}>▲ críticas + {d.incBreached} SLA vencido</div>
                </div>
              </div>
            </div>
            <div className="hud hw-reveal flex-1" style={{ animationDelay: '.18s' }}>
              <div className="hw-chdr"><h3>Feed en vivo</h3><span className="sub">alertas nivel alto+</span></div>
              <div className="flex max-h-[230px] flex-col overflow-y-auto">
                {feed.map((idx, i) => { const it = FEED[idx]; return (
                  <div className="hw-fe" key={`${idx}-${i}`}><span className="sev" style={{ background: `hsl(var(--${it[0]}))`, boxShadow: `0 0 6px hsl(var(--${it[0]}))` }} /><span className="ft">{new Date().toLocaleTimeString('es-CO', { hour: '2-digit', minute: '2-digit' })}</span><span className="fx">[{it[1]}] {it[2]}</span><span className="fa">{it[3]}</span></div>
                ); })}
              </div>
            </div>
          </div>
        </div>

        {/* map + quick/offline */}
        <div className="grid gap-4 lg:grid-cols-[1.35fr_1fr]">
          <div className="hud hw-reveal" style={{ animationDelay: '.2s' }}>
            <div className="hw-chdr"><h3>Ubicaciones · sedes</h3><span className="sub">{sedesActivas} activas</span></div>
            <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2 lg:grid-cols-3">
              {sedeList.map((s) => {
                const activa = s.estado === 'activa';
                const metric = s.agentes > 0 ? `${s.agentesActivos}/${s.agentes} agentes` : s.logins7d > 0 ? `${fmt(s.logins7d)} logins 7d` : '';
                return (
                  <div key={s.name} className="hw-clip flex flex-col gap-1.5 border border-border bg-secondary/20 p-2.5">
                    <div className="flex items-center gap-2.5">
                      <span className="hw-clip flex h-8 w-8 shrink-0 items-center justify-center bg-primary/12 text-primary"><Ico d="M12 21s-7-6-7-11a7 7 0 0 1 14 0c0 5-7 11-7 11z M12 10a1.6 1.6 0 1 0 0-3.2 1.6 1.6 0 0 0 0 3.2z" /></span>
                      <div className="min-w-0 flex-1">
                        <div className="truncate text-[13px] font-semibold">{s.name}</div>
                        <div className="hw-mono truncate text-[9.5px] uppercase tracking-wide text-muted-foreground">{s.region}{s.rol && <span className="text-primary"> · {s.rol}</span>}</div>
                      </div>
                      <span className="hw-mono flex shrink-0 items-center gap-1 text-[9.5px] uppercase" style={{ color: activa ? 'hsl(var(--success))' : 'hsl(var(--muted-foreground))' }}>
                        <span className="h-1.5 w-1.5 rounded-full" style={{ background: 'currentColor', boxShadow: activa ? '0 0 6px currentColor' : 'none' }} />{activa ? 'activa' : 'inactiva'}
                      </span>
                    </div>
                    {(metric || s.ultimaActividad) && (
                      <div className="hw-mono flex items-center justify-between border-t border-border/50 pt-1.5 text-[9.5px] text-muted-foreground">
                        <span className="truncate text-foreground/70">{metric || '—'}</span>
                        {s.ultimaActividad && <span className="shrink-0 pl-2">{relTime(s.ultimaActividad)}</span>}
                      </div>
                    )}
                  </div>
                );
              })}
              <div className="hw-clip flex items-center justify-center gap-2 border border-dashed border-border/70 p-2.5 text-muted-foreground">
                <Ico d="M12 5v14M5 12h14" /><span className="hw-mono text-[10px] uppercase tracking-wide">Agregar sede</span>
              </div>
            </div>
          </div>
          <div className="flex flex-col gap-4">
            <div className="hud hw-reveal" style={{ animationDelay: '.24s' }}>
              <div className="hw-chdr"><h3>Acción rápida</h3></div>
              <div className="grid grid-cols-3 gap-2">
                <Link to="/respuesta" className="hw-qab"><Ico d="M5 5l14 14" circle /><span>Bloquear IP</span></Link>
                <Link to="/velociraptor" className="hw-qab"><Ico d="M12 3 4 6v5c0 5 3.5 8 8 10 4.5-2 8-5 8-10V6z" /><span>Aislar host</span></Link>
                <Link to="/incidentes" className="hw-qab"><Ico d="M4 7h16v13H4z" /><span>Crear caso</span></Link>
              </div>
            </div>
            <div className="hud hw-reveal" style={{ animationDelay: '.28s' }}>
              <div className="hw-chdr"><h3>Offline</h3><span className="sub">7 días</span></div>
              <div className="flex items-baseline gap-2"><span className="hw-tabular text-[26px] font-bold">168</span><span className="hw-tag">equipos desconectados</span></div>
              <canvas ref={offRef} className="mt-1.5 block h-[120px] w-full" />
            </div>
          </div>
        </div>

        {/* trend */}
        <div className="hud hw-reveal" style={{ animationDelay: '.3s' }}>
          <div className="hw-chdr"><h3>Tendencia de seguridad</h3><div className="flex-1" />
            <div className="flex gap-0.5 bg-secondary/60 p-0.5">{(['24h', '7d', '30d', '90d'] as const).map((r) => <button key={r} className={`hw-tab ${range === r ? 'on' : ''}`} onClick={() => setRange(r)}>{r.toUpperCase()}</button>)}</div>
          </div>
          <div className="hw-legend mb-1.5">{([['destructive', 'Críticas'], ['warn-orange', 'Altas'], ['primary', 'Medias']] as [string, string][]).map((l) => <span key={l[1]}><i style={{ background: `hsl(var(--${l[0]}))` }} />{l[1]}</span>)}</div>
          <div className="relative h-[220px]"><canvas ref={trendRef} className="block h-[220px] w-full" /><div id="hw-ttip" ref={tipRef} className="hw-clip" /></div>
        </div>
      </div>
    </div>
  );
}

/** Icono inline mínimo (stroke). */
function Ico({ d, circle }: { d: string; circle?: boolean }) {
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">{circle && <circle cx="12" cy="12" r="9" />}<path d={d} strokeLinecap="round" strokeLinejoin="round" /></svg>;
}
