import { useEffect, useState } from 'react';
import { Share2, RefreshCw, AlertTriangle, CheckCircle2, UserX, Mail, Clock } from 'lucide-react';
import { permPostureApi, type PermPosture, type Guest } from '@/lib/permposture';

const RANGES = [{ d: '7d', l: '7 días' }, { d: '30d', l: '30 días' }, { d: '90d', l: '90 días' }];

function Kpi({ label, value, danger }: { label: string; value: number; danger?: boolean }) {
  return (
    <div className="glass rounded-lg p-3">
      <div className={`text-2xl font-bold ${danger && value > 0 ? 'text-red-500' : 'text-foreground'}`}>{value}</div>
      <div className="text-[11px] text-muted-foreground">{label}</div>
    </div>
  );
}

function GuestRow({ g }: { g: Guest }) {
  return (
    <div className="flex items-center justify-between gap-2 rounded bg-secondary/20 px-2.5 py-1.5 text-xs">
      <div className="min-w-0">
        <div className="flex items-center gap-1.5">
          <span className="truncate font-medium">{g.name}</span>
          {!g.enabled && <span className="inline-flex items-center gap-0.5 rounded bg-slate-500/15 px-1 text-[9px] text-slate-400"><UserX className="h-2.5 w-2.5" /> deshabilitado</span>}
          {g.freeMail && <span className="inline-flex items-center gap-0.5 rounded bg-amber-500/15 px-1 text-[9px] text-amber-500"><Mail className="h-2.5 w-2.5" /> correo gratis</span>}
          {g.stale && g.enabled && <span className="inline-flex items-center gap-0.5 rounded bg-orange-500/15 px-1 text-[9px] text-orange-400"><Clock className="h-2.5 w-2.5" /> &gt;180d</span>}
        </div>
        <p className="hw-mono truncate text-[10px] text-muted-foreground">{g.mail}</p>
      </div>
      <span className="shrink-0 text-[10px] text-muted-foreground/70">{g.created ? new Date(g.created).toLocaleDateString('es-CO') : '—'}</span>
    </div>
  );
}

export default function PermPosture() {
  const [days, setDays] = useState('30d');
  const [d, setD] = useState<PermPosture | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function load(dd: string) {
    setLoading(true); setErr(null);
    try { setD(await permPostureApi.get(dd)); }
    catch { setErr('No se pudo construir la postura de permisos (Graph).'); }
    finally { setLoading(false); }
  }
  useEffect(() => { void load(days); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [days]);

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-bold"><Share2 className="h-5 w-5 text-brand" /> Postura de Permisos (M365)</h1>
          <p className="text-sm text-muted-foreground">Quién tiene acceso externo al tenant: invitados, dominios y compartición externa/anónima en OneDrive/SharePoint.</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex rounded-lg border border-border bg-secondary/40 p-0.5">
            {RANGES.map((r) => <button key={r.d} onClick={() => setDays(r.d)} className={`rounded-md px-3 py-1 text-xs transition ${days === r.d ? 'bg-brand text-white' : 'text-muted-foreground hover:text-foreground'}`}>{r.l}</button>)}
          </div>
          <button onClick={() => void load(days)} disabled={loading} className="inline-flex items-center gap-1 rounded-lg border border-border bg-secondary/40 px-3 py-1.5 text-xs hover:bg-secondary disabled:opacity-50">
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} /> Actualizar
          </button>
        </div>
      </div>

      {err && <div className="flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-2 text-xs text-amber-600"><AlertTriangle className="h-4 w-4" /> {err}</div>}
      {d && !d.configured && <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-2 text-xs text-amber-600">Microsoft Graph no está configurado.</div>}

      {d && d.configured && (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
            <Kpi label="Invitados" value={d.kpis.invitados} />
            <Kpi label="Deshabilitados" value={d.kpis.deshabilitados} danger />
            <Kpi label="Dominios externos" value={d.kpis.dominios} />
            <Kpi label="Correo gratuito" value={d.kpis.correoGratis} danger />
            <Kpi label="Enlaces anónimos" value={d.kpis.enlacesAnonimos} danger />
            <Kpi label="Invitaciones ext." value={d.kpis.invitExternas} />
          </div>

          <div className="glass rounded-lg p-4">
            <p className="mb-2 text-sm font-semibold">Recomendaciones</p>
            <ul className="space-y-1">
              {d.recomendaciones.map((r, i) => (
                <li key={i} className="flex items-start gap-1.5 text-[11px] text-muted-foreground">
                  {r.startsWith('Sin ') ? <CheckCircle2 className="mt-0.5 h-3 w-3 shrink-0 text-emerald-500" /> : <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0 text-amber-500" />}<span>{r}</span>
                </li>
              ))}
            </ul>
          </div>

          <div className="grid gap-4 lg:grid-cols-3">
            <div className="lg:col-span-2 glass rounded-lg p-4">
              <p className="mb-3 text-sm font-semibold">Invitados externos ({d.invitados.length})</p>
              {d.invitados.length === 0 ? <p className="py-4 text-center text-xs text-muted-foreground">Sin invitados externos.</p> : (
                <div className="max-h-[400px] space-y-1 overflow-y-auto">{d.invitados.map((g, i) => <GuestRow key={i} g={g} />)}</div>
              )}
            </div>
            <div className="space-y-4">
              <div className="glass rounded-lg p-4">
                <p className="mb-2 text-sm font-semibold">Dominios con acceso</p>
                <div className="space-y-1">
                  {d.dominios.map((x) => <div key={x.dominio} className="flex justify-between text-[11px]"><span className="hw-mono truncate">{x.dominio}</span><span className="text-muted-foreground">{x.invitados}</span></div>)}
                </div>
              </div>
              {d.topSitiosAnonimos.length > 0 && (
                <div className="glass rounded-lg p-4">
                  <p className="mb-2 text-sm font-semibold">Sitios con enlaces anónimos</p>
                  <div className="space-y-1">
                    {d.topSitiosAnonimos.map((s) => <div key={s.site} className="flex justify-between gap-2 text-[10px]"><span className="hw-mono truncate">{s.site.replace(/^https?:\/\//, '')}</span><span className="text-muted-foreground">{s.count}</span></div>)}
                  </div>
                </div>
              )}
            </div>
          </div>
          <p className="text-center text-[11px] text-muted-foreground/60">Invitados vía Graph; compartición vía auditoría O365 ({d.range}). Actualizado {new Date(d.generatedAt).toLocaleTimeString('es-CO')}.</p>
        </>
      )}
      {loading && !d && <div className="glass h-40 animate-pulse rounded-lg" />}
    </div>
  );
}
