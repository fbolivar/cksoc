import { useEffect, useMemo, useState } from 'react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts';
import { Gauge, Server, HardDrive, RefreshCw, Cpu, AlertTriangle } from 'lucide-react';
import { obsApi, type Timeframe, type InvEntity, type ResPoint } from '@/lib/obs';

const TABS: { k: Timeframe; label: string }[] = [
  { k: 'hour', label: 'Hora' },
  { k: 'day', label: 'Día' },
  { k: 'week', label: 'Semana' },
  { k: 'month', label: 'Mes' },
  { k: 'year', label: 'Año' },
];

const COLORS = { cpu: '#38bdf8', mem: '#a78bfa', disk: '#34d399' };

interface Serie { ok: boolean; id: string; label: string; rol: string; kind: 'node' | 'vm'; vmid?: number; puntos: ResPoint[]; error?: string }

function fmtUptime(s: number | null): string {
  if (s == null) return '—';
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  return d > 0 ? `${d}d ${h}h` : `${h}h`;
}

function fmtTime(t: number, tf: Timeframe): string {
  const d = new Date(t);
  if (tf === 'hour' || tf === 'day') return d.toLocaleTimeString('es-CO', { hour: '2-digit', minute: '2-digit', hour12: false });
  if (tf === 'year') return d.toLocaleDateString('es-CO', { month: 'short', year: '2-digit' });
  return d.toLocaleDateString('es-CO', { day: '2-digit', month: '2-digit' });
}

function barColor(v: number | null): string {
  if (v == null) return 'bg-muted';
  if (v >= 90) return 'bg-red-500';
  if (v >= 75) return 'bg-amber-500';
  return 'bg-emerald-500';
}

function MiniBar({ label, value }: { label: string; value: number | null }) {
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-[11px] text-muted-foreground">
        <span>{label}</span>
        <span className="font-mono text-foreground">{value != null ? `${value}%` : '—'}</span>
      </div>
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-secondary/60">
        <div className={`h-full ${barColor(value)}`} style={{ width: `${Math.min(100, Math.max(0, value ?? 0))}%` }} />
      </div>
    </div>
  );
}

function InvCard({ e }: { e: InvEntity }) {
  const online = e.status === 'running' || e.status === 'online';
  const Icon = e.kind === 'node' ? Server : Cpu;
  return (
    <div className="glass rounded-lg p-4 space-y-3">
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-2">
          <Icon className="h-4 w-4 text-brand" />
          <div>
            <div className="text-sm font-semibold leading-tight">{e.label}</div>
            <div className="text-[11px] text-muted-foreground">{e.rol}</div>
          </div>
        </div>
        <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] ${online ? 'bg-emerald-500/10 text-emerald-500' : 'bg-red-500/10 text-red-500'}`}>
          <span className={`h-1.5 w-1.5 rounded-full ${online ? 'bg-emerald-500' : 'bg-red-500'}`} />
          {online ? 'Activo' : e.status}
        </span>
      </div>
      <MiniBar label="CPU" value={e.cpu} />
      <MiniBar label="RAM" value={e.mem} />
      <div className="flex justify-between text-[11px] text-muted-foreground">
        <span>RAM: {e.maxmemGB != null ? `${e.maxmemGB} GB` : '—'}</span>
        <span>Uptime: {fmtUptime(e.uptimeS)}</span>
      </div>
    </div>
  );
}

function ResChart({ s, tf }: { s: Serie; tf: Timeframe }) {
  const data = useMemo(() => s.puntos.map((p) => ({ ...p, label: fmtTime(p.t, tf) })), [s.puntos, tf]);
  const showDisk = s.kind === 'node';
  return (
    <div className="glass rounded-lg p-4">
      <div className="mb-2 flex items-center justify-between">
        <div className="text-sm font-semibold">{s.label}</div>
        <div className="text-[11px] text-muted-foreground">{s.rol}</div>
      </div>
      {!s.ok ? (
        <div className="flex h-[200px] items-center justify-center text-xs text-muted-foreground">
          Sin datos {s.error ? `(${s.error})` : ''}
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={200}>
          <AreaChart data={data} margin={{ top: 4, right: 8, left: -18, bottom: 0 }}>
            <defs>
              <linearGradient id={`g-cpu-${s.id}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={COLORS.cpu} stopOpacity={0.35} />
                <stop offset="95%" stopColor={COLORS.cpu} stopOpacity={0} />
              </linearGradient>
              <linearGradient id={`g-mem-${s.id}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={COLORS.mem} stopOpacity={0.35} />
                <stop offset="95%" stopColor={COLORS.mem} stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
            <XAxis dataKey="label" tick={{ fontSize: 10, fill: '#94a3b8' }} minTickGap={28} />
            <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: '#94a3b8' }} unit="%" width={40} />
            <Tooltip contentStyle={{ background: '#0b1220', border: '1px solid #1e293b', borderRadius: 8, fontSize: 12 }}
              labelStyle={{ color: '#e2e8f0' }} formatter={(v: number | string, n: string) => [v != null ? `${v}%` : '—', n]} />
            <Legend wrapperStyle={{ fontSize: 11 }} />
            <Area type="monotone" dataKey="cpu" name="CPU" stroke={COLORS.cpu} fill={`url(#g-cpu-${s.id})`} strokeWidth={1.8} dot={false} isAnimationActive={false} connectNulls />
            <Area type="monotone" dataKey="mem" name="RAM" stroke={COLORS.mem} fill={`url(#g-mem-${s.id})`} strokeWidth={1.8} dot={false} isAnimationActive={false} connectNulls />
            {showDisk && (
              <Area type="monotone" dataKey="disk" name="Disco" stroke={COLORS.disk} fill="transparent" strokeWidth={1.4} strokeDasharray="4 2" dot={false} isAnimationActive={false} connectNulls />
            )}
          </AreaChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}

const VMS = [
  { vmid: 100, label: 'Wazuh / SIEM', rol: 'Indexer + Manager' },
  { vmid: 101, label: 'Velociraptor', rol: 'DFIR' },
  { vmid: 102, label: 'Aplicación SOC', rol: 'HexWatch (backend + panel)' },
];

export default function Observabilidad() {
  const [tf, setTf] = useState<Timeframe>('day');
  const [inv, setInv] = useState<InvEntity[]>([]);
  const [invErr, setInvErr] = useState<string | null>(null);
  const [series, setSeries] = useState<Serie[]>([]);
  const [loading, setLoading] = useState(false);

  async function load(timeframe: Timeframe) {
    setLoading(true);
    try {
      const [inventory, node, ...vms] = await Promise.all([
        obsApi.inventory().catch(() => ({ ok: false, entidades: [], error: 'sin conexión' })),
        obsApi.node(timeframe).catch((e) => ({ ok: false, node: '', puntos: [], error: String(e?.message ?? e) })),
        ...VMS.map((v) => obsApi.vm(v.vmid, timeframe).catch((e) => ({ ok: false, vmid: v.vmid, puntos: [], error: String(e?.message ?? e) }))),
      ]);
      setInv(inventory.entidades ?? []);
      setInvErr(inventory.ok ? null : (inventory.error ?? 'Proxmox no disponible'));
      const built: Serie[] = [
        { ok: node.ok, id: 'node', label: `Hypervisor (${node.node || 'pmx-soc'})`, rol: 'Proxmox VE', kind: 'node', puntos: node.puntos, error: node.error },
        ...vms.map((r, i) => ({ ok: r.ok, id: `vm${VMS[i].vmid}`, label: VMS[i].label, rol: VMS[i].rol, kind: 'vm' as const, vmid: VMS[i].vmid, puntos: r.puntos, error: (r as { error?: string }).error })),
      ];
      setSeries(built);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { void load(tf); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [tf]);

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-bold"><Gauge className="h-5 w-5 text-brand" /> Observabilidad · Recursos</h1>
          <p className="text-sm text-muted-foreground">Tendencia histórica de CPU, memoria y disco de la infraestructura del SOC (hypervisor y máquinas virtuales).</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex rounded-lg border border-border bg-secondary/40 p-0.5">
            {TABS.map((t) => (
              <button key={t.k} onClick={() => setTf(t.k)}
                className={`rounded-md px-3 py-1 text-xs transition ${tf === t.k ? 'bg-brand text-white' : 'text-muted-foreground hover:text-foreground'}`}>
                {t.label}
              </button>
            ))}
          </div>
          <button onClick={() => void load(tf)} disabled={loading}
            className="inline-flex items-center gap-1 rounded-lg border border-border bg-secondary/40 px-3 py-1.5 text-xs hover:bg-secondary disabled:opacity-50">
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} /> Actualizar
          </button>
        </div>
      </div>

      {invErr && (
        <div className="flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-2 text-xs text-amber-600">
          <AlertTriangle className="h-4 w-4" /> No se pudo consultar Proxmox ({invErr}). Verifica el token de solo lectura y la conectividad al hypervisor.
        </div>
      )}

      <div>
        <div className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground"><HardDrive className="h-3.5 w-3.5" /> Estado actual</div>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {inv.length === 0
            ? Array.from({ length: 4 }).map((_, i) => <div key={i} className="glass h-[150px] animate-pulse rounded-lg" />)
            : inv.map((e) => <InvCard key={e.id} e={e} />)}
        </div>
      </div>

      <div>
        <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Tendencia ({TABS.find((t) => t.k === tf)?.label})</div>
        <div className="grid gap-3 lg:grid-cols-2">
          {series.map((s) => <ResChart key={s.id} s={s} tf={tf} />)}
        </div>
      </div>
    </div>
  );
}
