import { useEffect, useState } from 'react';
import { Radar, RefreshCw, AlertTriangle, ExternalLink, CheckCircle2, Settings2, Lock } from 'lucide-react';
import { darkwebApi, type DwRadar, type DwFinding, type DwSource, type Sev } from '@/lib/darkweb';

const SEV: Record<Sev, { cls: string; txt: string }> = {
  critica: { cls: 'bg-red-500/15 text-red-500 border-red-500/40', txt: 'CRÍTICA' },
  alta: { cls: 'bg-orange-500/15 text-orange-400 border-orange-500/40', txt: 'ALTA' },
  media: { cls: 'bg-amber-500/15 text-amber-500 border-amber-500/40', txt: 'MEDIA' },
  baja: { cls: 'bg-slate-500/15 text-slate-400 border-slate-500/40', txt: 'BAJA' },
};

function SourceCard({ s }: { s: DwSource }) {
  const m = s.estado === 'activo'
    ? { icon: <CheckCircle2 className="h-4 w-4 text-emerald-500" />, cls: 'border-emerald-500/30', tag: 'Activo', tcls: 'text-emerald-500' }
    : s.estado === 'requiere_config'
      ? { icon: <Settings2 className="h-4 w-4 text-amber-500" />, cls: 'border-amber-500/30', tag: 'Requiere configuración', tcls: 'text-amber-500' }
      : { icon: <Lock className="h-4 w-4 text-slate-400" />, cls: 'border-slate-500/30', tag: 'Requiere feed', tcls: 'text-slate-400' };
  return (
    <div className={`glass rounded-lg border ${m.cls} p-3`}>
      <div className="flex items-center gap-2">{m.icon}<span className="text-xs font-semibold">{s.label}</span></div>
      <div className={`mt-1 text-[10px] font-medium ${m.tcls}`}>{m.tag}</div>
      <p className="mt-1 text-[11px] text-muted-foreground">{s.nota}</p>
    </div>
  );
}

function FindingRow({ f }: { f: DwFinding }) {
  const s = SEV[f.severity];
  return (
    <div className="rounded border-l-2 border-l-border bg-secondary/20 px-2.5 py-1.5">
      <div className="flex items-center justify-between gap-2">
        <span className="truncate text-xs font-medium">{f.title}</span>
        <div className="flex shrink-0 items-center gap-1.5">
          <span className={`rounded border px-1.5 py-0.5 text-[9px] font-semibold ${s.cls}`}>{s.txt}</span>
          <span className="rounded bg-secondary px-1.5 py-0.5 text-[9px] uppercase text-muted-foreground">{f.source}</span>
        </div>
      </div>
      <p className="hw-mono mt-0.5 flex items-center gap-1.5 truncate text-[10px] text-muted-foreground">
        {f.detail}
        {f.date && <span>· {new Date(f.date).toLocaleDateString('es-CO')}</span>}
        {f.url && <a href={f.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-0.5 text-primary hover:underline"><ExternalLink className="h-3 w-3" /> ver</a>}
      </p>
    </div>
  );
}

function Kpi({ label, value, danger }: { label: string; value: number; danger?: boolean }) {
  return (
    <div className="glass rounded-lg p-3">
      <div className={`text-2xl font-bold ${danger && value > 0 ? 'text-red-500' : 'text-foreground'}`}>{value}</div>
      <div className="text-[11px] text-muted-foreground">{label}</div>
    </div>
  );
}

export default function DarkWeb() {
  const [d, setD] = useState<DwRadar | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function load(refresh = false) {
    setLoading(true); setErr(null);
    try { setD(refresh ? await darkwebApi.refresh() : await darkwebApi.get()); }
    catch { setErr('No se pudo construir el radar de fugas.'); }
    finally { setLoading(false); }
  }
  useEffect(() => { void load(false); }, []);

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-bold"><Radar className="h-5 w-5 text-brand" /> Dark Web Radar</h1>
          <p className="text-sm text-muted-foreground">Centro de fugas: dónde aparece el cliente en fuentes de exposición (extorsión, brechas de credenciales, repos públicos).</p>
        </div>
        <button onClick={() => void load(true)} disabled={loading} className="inline-flex items-center gap-1 rounded-lg border border-border bg-secondary/40 px-3 py-1.5 text-xs hover:bg-secondary disabled:opacity-50">
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} /> Recalcular
        </button>
      </div>

      <div className="flex items-start gap-2 rounded-lg border border-border bg-secondary/20 px-4 py-2 text-[11px] text-muted-foreground">
        <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted-foreground" />
        Cubre fuentes OSINT accesibles. Solo se busca por el <b>dominio público</b> del cliente, nunca por correos o nombres. El dark web profundo (mercados/foros Tor) y los pastes requieren un feed comercial — se indican abajo como fuentes a activar.
      </div>

      {err && <div className="flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-2 text-xs text-amber-600"><AlertTriangle className="h-4 w-4" /> {err}</div>}

      {d && (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Kpi label="Fugas totales" value={d.kpis.total} danger />
            <Kpi label="Credenciales" value={d.kpis.credenciales} danger />
            <Kpi label="Extorsión directa" value={d.kpis.ransomware} danger />
            <Kpi label="GitHub público" value={d.kpis.github} danger />
          </div>

          <div>
            <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Cobertura de fuentes</div>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {d.fuentes.map((s) => <SourceCard key={s.key} s={s} />)}
            </div>
          </div>

          <div className="glass rounded-lg p-4">
            <p className="mb-3 text-sm font-semibold">Hallazgos de fuga</p>
            {d.hallazgos.length === 0 ? (
              <p className="py-6 text-center text-xs text-muted-foreground">Sin fugas detectadas en las fuentes activas. 👍</p>
            ) : (
              <div className="max-h-[460px] space-y-1.5 overflow-y-auto">
                {d.hallazgos.map((f, i) => <FindingRow key={i} f={f} />)}
              </div>
            )}
          </div>

          <p className="text-center text-[11px] text-muted-foreground/60">Actualizado {new Date(d.generatedAt).toLocaleString('es-CO')}.</p>
        </>
      )}
      {loading && !d && <div className="glass h-40 animate-pulse rounded-lg" />}
    </div>
  );
}
