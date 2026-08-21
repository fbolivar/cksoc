/**
 * Dashboard Office 365 — visibilidad de la auditoría de M365 (Management Activity
 * API) que Wazuh ingesta: usuarios, IPs cliente (con país), operaciones,
 * workloads, reglas, sign-ins de Azure AD y actividad de archivos.
 */
import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { AxiosError } from 'axios';
import { Cloud, RefreshCw, Loader2, Users, Globe2, LogIn, Download, FileText, UserCog, UserCheck, ShieldOff, UserPlus } from 'lucide-react';
import { office365Api, type O365Overview, type NamedCount, type M365Directory } from '@/lib/office365';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

type Range = '24h' | '7d' | '30d';
const RANGES: Range[] = ['24h', '7d', '30d'];
const fmt = (n: number) => n.toLocaleString('es-CO');
// Etiqueta usuarios raros (tokens de SharePoint anónimo/sistema).
const cleanUser = (u: string) => u.startsWith('urn:spo:') ? 'SharePoint (sistema/anónimo)' : u;

const WL_COLOR: Record<string, string> = {
  Exchange: 'primary', OneDrive: 'cyan', SharePoint: 'warn-orange', AzureActiveDirectory: 'destructive',
  MicrosoftTeams: 'success', SecurityComplianceCenter: 'destructive', PowerPlatform: 'primary', Copilot: 'cyan',
};

function Kpi({ label, value, icon: Icon, danger }: { label: string; value: string; icon: typeof Users; danger?: boolean }) {
  return (
    <Card><CardContent className="p-4">
      <p className="flex items-center gap-1.5 text-xs text-muted-foreground"><Icon className="h-3.5 w-3.5" /> {label}</p>
      <p className="text-2xl font-bold tabular-nums" style={danger ? { color: 'hsl(var(--destructive))' } : undefined}>{value}</p>
    </CardContent></Card>
  );
}

function BarList({ title, icon: Icon, items, max, mono, onClick, suffix, footer }: {
  title: string; icon?: typeof Users; items: { label: string; count: number; note?: string }[]; max: number;
  mono?: boolean; onClick?: (label: string) => void; suffix?: string; footer?: React.ReactNode;
}) {
  return (
    <Card><CardContent className="p-4">
      <p className="mb-3 flex items-center gap-2 text-sm font-semibold">{Icon && <Icon className="h-4 w-4 text-muted-foreground" />} {title}</p>
      {items.length === 0 ? <p className="py-4 text-center text-xs text-muted-foreground">Sin datos</p> : (
        <div className="space-y-2">
          {items.map((it, i) => (
            <div key={i} className={onClick ? 'cursor-pointer' : ''} onClick={onClick ? () => onClick(it.label) : undefined}>
              <div className="flex items-center justify-between gap-2">
                <span className={`truncate text-xs ${mono ? 'hw-mono' : ''} ${onClick ? 'hover:text-primary' : ''}`}>{it.label}{it.note ? <span className="text-muted-foreground"> · {it.note}</span> : ''}</span>
                <span className="hw-tabular shrink-0 text-[11px] text-muted-foreground">{fmt(it.count)}{suffix ?? ''}</span>
              </div>
              <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-secondary"><div className="h-full rounded-full bg-primary" style={{ width: `${Math.max(3, (it.count / max) * 100)}%` }} /></div>
            </div>
          ))}
        </div>
      )}
      {footer}
    </CardContent></Card>
  );
}

export default function Office365() {
  const [range, setRange] = useState<Range>('7d');
  const [d, setD] = useState<O365Overview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showInfra, setShowInfra] = useState(false);
  const navigate = useNavigate();

  async function load(r: Range) {
    setLoading(true); setError(null);
    try { setD(await office365Api.overview(r)); }
    catch (e) { setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo cargar el dashboard de Office 365'); }
    finally { setLoading(false); }
  }
  useEffect(() => { load(range); }, [range]);

  // Directorio M365 vía Graph (independiente del rango; se carga una vez).
  const [ident, setIdent] = useState<M365Directory | null>(null);
  const [identErr, setIdentErr] = useState<string | null>(null);
  const [identLoading, setIdentLoading] = useState(true);
  useEffect(() => {
    office365Api.identities()
      .then(setIdent)
      .catch((e) => setIdentErr((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo consultar el directorio M365'))
      .finally(() => setIdentLoading(false));
  }, []);

  const maxTl = useMemo(() => Math.max(1, ...(d?.timeline ?? []).map((t) => t.count)), [d]);
  const nc = (arr: NamedCount[], clean = false) => arr.map((x) => ({ label: clean ? cleanUser(x.key) : x.key, count: x.count, note: x.country }));
  // Separa IPs de personas reales de la infraestructura de Microsoft (usuario de sistema urn:...).
  const realIps = useMemo(() => (d?.topClientIps ?? []).filter((x) => !x.system), [d]);
  const infraIps = useMemo(() => (d?.topClientIps ?? []).filter((x) => x.system), [d]);
  const goUser = (u: string) => navigate(`/alertas?q=${encodeURIComponent(u)}`);
  const goIp = (ip: string) => navigate(`/alertas?srcip=${encodeURIComponent(ip)}`);

  return (
    <div className="mx-auto max-w-6xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 hw-mono text-2xl font-bold tracking-tight"><Cloud className="h-6 w-6 text-neon" /> Office 365</h1>
          <p className="text-sm text-muted-foreground">Auditoría de M365 (Azure AD, Exchange, OneDrive, SharePoint, Teams…)</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex overflow-hidden rounded-md border border-input">
            {RANGES.map((r) => <button key={r} onClick={() => setRange(r)} className={`px-3 py-1.5 text-xs ${range === r ? 'bg-secondary font-semibold text-foreground' : 'text-muted-foreground hover:bg-secondary/50'}`}>{r}</button>)}
          </div>
          <Button variant="outline" size="sm" onClick={() => load(range)} disabled={loading}><RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} /></Button>
        </div>
      </div>

      {error && <Card><CardContent className="p-4 text-sm text-amber-700">{error}</CardContent></Card>}

      {loading && !d ? (
        <p className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Cargando auditoría de Office 365…</p>
      ) : d && (
        <>
          {/* KPIs */}
          <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-6">
            <Kpi label="Eventos" value={fmt(d.total)} icon={Cloud} />
            <Kpi label="Usuarios" value={fmt(d.users)} icon={Users} />
            <Kpi label="IPs cliente" value={fmt(d.clientIps)} icon={Globe2} />
            <Kpi label="Sign-ins" value={fmt(d.signIns)} icon={LogIn} />
            <Kpi label="Sign-ins fallidos" value={fmt(d.signInsFailed)} icon={LogIn} danger={d.signInsFailed > 0} />
            <Kpi label="Descargas" value={fmt(d.downloads)} icon={Download} danger={d.downloads > 0} />
          </div>

          {/* Timeline */}
          <Card><CardContent className="p-4">
            <p className="mb-3 text-sm font-semibold">Actividad en el tiempo</p>
            <div className="flex h-24 items-end gap-0.5">
              {d.timeline.map((t, i) => (
                <div key={i} className="flex-1 rounded-t bg-primary/70 transition-all hover:bg-primary" style={{ height: `${Math.max(2, (t.count / maxTl) * 100)}%` }}
                  title={`${new Date(t.ts).toLocaleString('es-CO')}: ${fmt(t.count)}`} />
              ))}
            </div>
          </CardContent></Card>

          {/* Workloads */}
          <Card><CardContent className="p-4">
            <p className="mb-3 text-sm font-semibold">Workloads (servicios de M365)</p>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
              {d.workloads.map((w) => {
                const c = WL_COLOR[w.key] ?? 'muted-foreground';
                return (
                  <div key={w.key} className="hw-clip border border-border bg-secondary/20 p-2.5 text-center">
                    <div className="hw-tabular text-lg font-bold" style={{ color: `hsl(var(--${c}))` }}>{fmt(w.count)}</div>
                    <div className="hw-mono truncate text-[9.5px] uppercase text-muted-foreground" title={w.key}>{w.key.replace('AzureActiveDirectory', 'Azure AD').replace('SecurityComplianceCenter', 'Security & Compl.').replace('Microsoft', '')}</div>
                  </div>
                );
              })}
            </div>
          </CardContent></Card>

          {/* Identidades M365 (Microsoft Graph) — directorio en vivo */}
          <Card><CardContent className="p-4">
            <div className="mb-3 flex items-center justify-between gap-2">
              <p className="flex items-center gap-2 text-sm font-semibold"><UserCog className="h-4 w-4 text-muted-foreground" /> Identidades M365 · Microsoft Graph</p>
              <span className="hw-mono text-[10px] uppercase tracking-widest text-muted-foreground">directorio en vivo</span>
            </div>
            {identLoading ? (
              <p className="flex items-center gap-2 py-4 text-xs text-muted-foreground"><Loader2 className="h-3.5 w-3.5 animate-spin" /> Consultando el directorio del tenant…</p>
            ) : identErr ? (
              <p className="py-3 text-xs text-amber-700">{identErr}</p>
            ) : !ident?.configured ? (
              <p className="py-3 text-xs text-muted-foreground">Microsoft Graph no está configurado (define GRAPH_TENANT_ID / GRAPH_CLIENT_ID / GRAPH_CLIENT_SECRET).</p>
            ) : (
              <>
                <div className="grid gap-3 sm:grid-cols-4">
                  <Kpi label="Usuarios" value={fmt(ident.total)} icon={Users} />
                  <Kpi label="Habilitados" value={fmt(ident.enabled)} icon={UserCheck} />
                  <Kpi label="Deshabilitados" value={fmt(ident.disabled)} icon={ShieldOff} danger={ident.disabled > 0} />
                  <Kpi label="Invitados externos" value={fmt(ident.guests)} icon={UserPlus} danger={ident.guests > 0} />
                </div>
                <div className="mt-4 grid gap-4 lg:grid-cols-2">
                  <div>
                    <p className="mb-1.5 text-[11px] font-medium text-muted-foreground">Invitados externos (revisión de gobernanza)</p>
                    {ident.guestList.length === 0 ? <p className="text-xs text-muted-foreground">Ninguno</p> : ident.guestList.map((u, i) => (
                      <div key={i} className="flex items-center justify-between gap-2 py-0.5 text-xs">
                        <span className="shrink-0 truncate cursor-pointer hover:text-primary" onClick={() => goUser(u.upn)} title={u.upn}>{u.displayName}</span>
                        <span className="hw-mono max-w-[55%] truncate text-[10px] text-muted-foreground" title={u.upn}>{u.upn}</span>
                      </div>
                    ))}
                  </div>
                  <div>
                    <p className="mb-1.5 text-[11px] font-medium text-muted-foreground">Cuentas recientes</p>
                    {ident.recent.map((u, i) => (
                      <div key={i} className="flex items-center justify-between gap-2 py-0.5 text-xs">
                        <span className="truncate cursor-pointer hover:text-primary" onClick={() => goUser(u.upn)} title={u.upn}>
                          <span className="mr-1.5 inline-block h-1.5 w-1.5 rounded-full align-middle" style={{ background: u.enabled ? 'hsl(var(--success))' : 'hsl(var(--destructive))' }} />
                          {u.displayName}
                        </span>
                        <span className="hw-mono shrink-0 text-[10px] text-muted-foreground">{u.created ? u.created.slice(0, 10) : '—'}</span>
                      </div>
                    ))}
                  </div>
                </div>
                {ident.disabled > 0 && (
                  <div className="mt-3">
                    <p className="mb-1.5 text-[11px] font-medium text-muted-foreground">Cuentas deshabilitadas</p>
                    <div className="flex flex-wrap gap-1.5">
                      {ident.disabledList.map((u, i) => <span key={i} className="hw-mono rounded bg-secondary px-2 py-0.5 text-[10px]" title={u.upn}>{u.displayName}</span>)}
                    </div>
                  </div>
                )}
                <p className="mt-3 text-[10px] text-muted-foreground/60">Fuente: Microsoft Graph · GET /users (solo lectura){ident.truncated ? ' · muestra parcial (>999)' : ''} · {new Date(ident.generatedAt).toLocaleTimeString('es-CO')}</p>
              </>
            )}
          </CardContent></Card>

          {/* Sign-ins (Azure AD) + Actividad de archivos */}
          <div className="grid gap-4 lg:grid-cols-2">
            <Card><CardContent className="p-4">
              <p className="mb-3 flex items-center gap-2 text-sm font-semibold"><LogIn className="h-4 w-4 text-muted-foreground" /> Sign-ins de Azure AD</p>
              <div className="mb-3 flex gap-4 text-sm"><span>Exitosos: <b className="text-foreground">{fmt(d.signIns)}</b></span><span>Fallidos: <b style={{ color: d.signInsFailed > 0 ? 'hsl(var(--destructive))' : undefined }}>{fmt(d.signInsFailed)}</b></span></div>
              <div className="grid gap-3 sm:grid-cols-2">
                <div>
                  <p className="mb-1.5 text-[11px] font-medium text-muted-foreground">Top usuarios</p>
                  {d.signInUsers.slice(0, 6).map((u, i) => <div key={i} className="flex items-center justify-between gap-2 py-0.5 text-xs"><span className="truncate cursor-pointer hover:text-primary" onClick={() => goUser(u.key)}>{cleanUser(u.key)}</span><span className="text-muted-foreground">{u.count}</span></div>)}
                </div>
                <div>
                  <p className="mb-1.5 text-[11px] font-medium text-muted-foreground">Origen (IP · país)</p>
                  {d.signInIps.slice(0, 6).map((ip, i) => <div key={i} className="flex items-center justify-between gap-2 py-0.5 text-xs"><span className="hw-mono truncate cursor-pointer hover:text-primary" onClick={() => goIp(ip.key)}>{ip.key} <span className="text-muted-foreground">{ip.country}</span></span><span className="text-muted-foreground">{ip.count}</span></div>)}
                </div>
              </div>
            </CardContent></Card>

            <BarList title="Actividad de archivos · posible exfiltración" icon={FileText} onClick={goUser}
              items={d.fileTopUsers.map((u) => ({ label: cleanUser(u.key), count: u.count }))}
              max={Math.max(1, ...d.fileTopUsers.map((u) => u.count))} />
          </div>

          {/* Top usuarios / IPs / operaciones / reglas */}
          <div className="grid gap-4 lg:grid-cols-2">
            <BarList title="Top usuarios" icon={Users} onClick={goUser}
              items={nc(d.topUsers, true)} max={Math.max(1, ...d.topUsers.map((x) => x.count))} />
            <BarList title="Top IPs cliente (con país)" icon={Globe2} mono onClick={goIp}
              items={(showInfra ? d.topClientIps : realIps).map((x) => ({ label: x.key, count: x.count, note: x.system ? `${x.country || 'MS'} · infra MS` : x.country }))}
              max={Math.max(1, ...(showInfra ? d.topClientIps : realIps).map((x) => x.count), 1)}
              footer={infraIps.length > 0 && (
                <button onClick={() => setShowInfra((v) => !v)} className="mt-3 w-full rounded-md border border-dashed border-border py-1.5 text-[11px] text-muted-foreground hover:text-foreground">
                  {showInfra
                    ? '▲ Ocultar infraestructura Microsoft'
                    : `▾ ${infraIps.length} IP${infraIps.length > 1 ? 's' : ''} de infraestructura Microsoft ocultas (sync/sistema, no personas)`}
                </button>
              )} />
            <BarList title="Top operaciones" items={d.topOperations.map((x) => ({ label: x.key, count: x.count }))}
              max={Math.max(1, ...d.topOperations.map((x) => x.count))} />
            <BarList title="Top reglas (por evento)" items={d.topRules.map((r) => ({ label: r.desc, count: r.count, note: `nivel ${r.level}` }))}
              max={Math.max(1, ...d.topRules.map((r) => r.count))} />
          </div>

          <p className="text-center text-[11px] text-muted-foreground/60">
            Fuente: Office 365 Management Activity API vía Wazuh. Actualizado {new Date(d.generatedAt).toLocaleTimeString('es-CO')}.
          </p>
        </>
      )}
    </div>
  );
}
