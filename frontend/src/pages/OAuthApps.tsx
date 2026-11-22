import { useEffect, useState } from 'react';
import { KeyRound, RefreshCw, AlertTriangle, BadgeCheck, Mail, Building2, User } from 'lucide-react';
import { oauthAppsApi, type OAuthOverview, type OAuthApp, type Risk } from '@/lib/oauthapps';

const RISK: Record<Risk, { cls: string; txt: string }> = {
  critica: { cls: 'bg-red-500/15 text-red-500 border-red-500/40', txt: 'CRÍTICA' },
  alta: { cls: 'bg-orange-500/15 text-orange-400 border-orange-500/40', txt: 'ALTA' },
  media: { cls: 'bg-amber-500/15 text-amber-500 border-amber-500/40', txt: 'MEDIA' },
  baja: { cls: 'bg-slate-500/15 text-slate-400 border-slate-500/40', txt: 'BAJA' },
};

function Kpi({ label, value, danger }: { label: string; value: number; danger?: boolean }) {
  return (
    <div className="glass rounded-lg p-3">
      <div className={`text-2xl font-bold ${danger && value > 0 ? 'text-red-500' : 'text-foreground'}`}>{value}</div>
      <div className="text-[11px] text-muted-foreground">{label}</div>
    </div>
  );
}

function AppRow({ a }: { a: OAuthApp }) {
  const r = RISK[a.risk];
  return (
    <div className={`rounded border-l-2 px-3 py-2 ${a.risk === 'critica' ? 'border-l-red-500 bg-red-500/5' : a.risk === 'alta' ? 'border-l-orange-500/60 bg-secondary/30' : 'border-l-border bg-secondary/20'}`}>
      <div className="flex items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <span className="truncate text-sm font-medium">{a.name}</span>
          {a.verified ? <BadgeCheck className="h-3.5 w-3.5 shrink-0 text-emerald-500" aria-label="Editor verificado" /> : !a.firstParty && <span className="shrink-0 rounded bg-amber-500/15 px-1 text-[9px] text-amber-600">sin verificar</span>}
          {a.firstParty && <span className="shrink-0 rounded bg-secondary px-1 text-[9px] text-muted-foreground">Microsoft</span>}
          {a.mailAccess && <Mail className="h-3.5 w-3.5 shrink-0 text-red-400" aria-label="Acceso a correo" />}
        </div>
        <span className={`shrink-0 rounded border px-1.5 py-0.5 text-[9px] font-semibold ${r.cls}`}>{r.txt}</span>
      </div>
      <div className="mt-1 flex flex-wrap items-center gap-1.5 text-[10px] text-muted-foreground">
        {a.consent === 'organizacion'
          ? <span className="inline-flex items-center gap-0.5 text-amber-600"><Building2 className="h-3 w-3" /> toda la organización</span>
          : <span className="inline-flex items-center gap-0.5"><User className="h-3 w-3" /> {a.usuarios} usuario(s)</span>}
        {a.appRoles.map((p, i) => <span key={'r' + i} className="rounded bg-red-500/15 px-1.5 py-0.5 font-mono text-red-500">app:{p}</span>)}
        {a.scopes.slice(0, 10).map((p, i) => <span key={'s' + i} className="rounded bg-secondary px-1.5 py-0.5 font-mono">{p}</span>)}
        {a.scopes.length > 10 && <span>+{a.scopes.length - 10}</span>}
      </div>
      {a.reasons.length > 0 && <p className="mt-1 text-[10px] text-muted-foreground/70">{a.reasons.join(' · ')}</p>}
    </div>
  );
}

export default function OAuthApps() {
  const [d, setD] = useState<OAuthOverview | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [soloTerceros, setSoloTerceros] = useState(true);
  const [refMsg, setRefMsg] = useState<string | null>(null);

  async function load() {
    setLoading(true); setErr(null);
    try { setD(await oauthAppsApi.get()); }
    catch { setErr('No se pudo consultar los consentimientos OAuth (Microsoft Graph).'); }
    finally { setLoading(false); }
  }
  useEffect(() => { void load(); }, []);

  async function onRefresh() {
    setRefMsg(null);
    try { const r = await oauthAppsApi.refresh(); setRefMsg(`Chequeo: ${r.nuevas} app(s) riesgosa(s) nueva(s).`); await load(); }
    catch { setRefMsg('No se pudo refrescar.'); }
  }

  const apps = (d?.apps ?? []).filter((a) => !soloTerceros || !a.firstParty);

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-bold"><KeyRound className="h-5 w-5 text-brand" /> Consentimientos OAuth (M365)</h1>
          <p className="text-sm text-muted-foreground">Apps de terceros con consentimiento en el tenant y su riesgo. Detecta "consent phishing": apps que leen correo o datos sin contraseña.</p>
        </div>
        <div className="flex items-center gap-2">
          <label className="flex items-center gap-1.5 text-xs text-muted-foreground"><input type="checkbox" className="h-3.5 w-3.5 accent-brand" checked={soloTerceros} onChange={(e) => setSoloTerceros(e.target.checked)} /> Solo terceros</label>
          <button onClick={() => void onRefresh()} disabled={loading} className="inline-flex items-center gap-1 rounded-lg border border-border bg-secondary/40 px-3 py-1.5 text-xs hover:bg-secondary disabled:opacity-50">
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} /> Actualizar
          </button>
        </div>
      </div>

      {refMsg && <div className="rounded-lg border border-border bg-secondary/30 px-4 py-2 text-xs text-muted-foreground">{refMsg}</div>}
      {err && <div className="flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-2 text-xs text-amber-600"><AlertTriangle className="h-4 w-4" /> {err}</div>}
      {d && !d.configured && <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-2 text-xs text-amber-600">Microsoft Graph no está configurado (GRAPH_TENANT_ID/CLIENT_ID/CLIENT_SECRET).</div>}

      {d && d.configured && (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
            <Kpi label="Apps totales" value={d.kpis.total} />
            <Kpi label="De terceros" value={d.kpis.terceros} />
            <Kpi label="Riesgosas" value={d.kpis.riesgosas} danger />
            <Kpi label="Editor no verificado" value={d.kpis.sinEditor} danger />
            <Kpi label="Consentidas por la org" value={d.kpis.orgConsent} danger />
            <Kpi label="Con acceso a correo" value={d.kpis.conCorreo} danger />
          </div>
          <div className="glass rounded-lg p-4">
            <p className="mb-3 text-sm font-semibold">Aplicaciones con consentimiento ({apps.length})</p>
            {apps.length === 0 ? (
              <p className="py-6 text-center text-xs text-muted-foreground">Sin apps en este filtro.</p>
            ) : (
              <div className="max-h-[560px] space-y-1.5 overflow-y-auto">{apps.map((a) => <AppRow key={a.spId} a={a} />)}</div>
            )}
          </div>
          <p className="text-center text-[11px] text-muted-foreground/60">Para revocar: M365 → Enterprise applications → la app → Permissions. Actualizado {new Date(d.generatedAt).toLocaleTimeString('es-CO')}.</p>
        </>
      )}
      {loading && !d && <div className="glass h-40 animate-pulse rounded-lg" />}
    </div>
  );
}
