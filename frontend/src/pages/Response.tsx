/**
 * Respuesta a incidentes (human-in-the-loop).
 * Cola de incidentes -> investigar -> bloquear (con confirmacion) -> auditoria.
 * El bloqueo lo ejecuta la app en el FortiGate SOLO tras confirmacion de un admin.
 */
import { useEffect, useState } from 'react';
import { AxiosError } from 'axios';
import {
  ShieldAlert, ShieldX, ShieldCheck, RotateCcw, Search, Server,
  MapPin, Activity, CheckCircle2, XCircle, Ban, RefreshCw, AlertTriangle,
} from 'lucide-react';
import { useAuth } from '@/lib/auth';
import {
  responseApi, abuseColor,
  type Incident, type ResponseStatus, type BlockedItem, type AuditRow,
} from '@/lib/response';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { BlockModal } from '@/components/response/BlockModal';

type Tab = 'incidentes' | 'bloqueadas' | 'auditoria';

export default function Response() {
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';
  const [tab, setTab] = useState<Tab>('incidentes');
  const [status, setStatus] = useState<ResponseStatus | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [blocked, setBlocked] = useState<BlockedItem[]>([]);
  const [audit, setAudit] = useState<AuditRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [modalIp, setModalIp] = useState<{ ip: string; context?: string } | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [threatsOnly, setThreatsOnly] = useState(true);
  const [msg, setMsg] = useState<{ k: 'ok' | 'err'; t: string } | null>(null);

  const flash = (k: 'ok' | 'err', t: string) => {
    setMsg({ k, t });
    setTimeout(() => setMsg(null), 4500);
  };
  const err = (e: unknown) =>
    flash('err', (e as AxiosError<{ error?: string }>).response?.data?.error ?? 'Error');

  async function reloadAll() {
    setLoading(true);
    try {
      const [st, inc, bl, au] = await Promise.all([
        responseApi.status(),
        responseApi.incidents(168, threatsOnly).catch(() => []),
        responseApi.blocked().catch(() => []),
        responseApi.history().catch(() => []),
      ]);
      setStatus(st); setIncidents(inc); setBlocked(bl); setAudit(au);
    } finally {
      setLoading(false);
    }
  }
  // Recarga al montar y cuando cambia el toggle "Solo amenazas".
  useEffect(() => { reloadAll().catch(() => err('No se pudo cargar')); /* eslint-disable-next-line */ }, [threatsOnly]);

  async function confirmBlock(ip: string, motivo: string) {
    await responseApi.block(ip, motivo);
    setModalIp(null);
    flash('ok', `IP ${ip} bloqueada`);
    await reloadAll();
  }
  async function doUnblock(ip: string) {
    if (!confirm(`¿Desbloquear ${ip}?`)) return;
    try {
      await responseApi.unblock(ip);
      flash('ok', `IP ${ip} desbloqueada`);
      await reloadAll();
    } catch (e) { err(e); }
  }

  const tabs: { id: Tab; label: string; icon: typeof ShieldAlert; n?: number }[] = [
    { id: 'incidentes', label: 'IPs sospechosas', icon: ShieldAlert, n: incidents.length },
    { id: 'bloqueadas', label: 'IPs bloqueadas', icon: Ban, n: blocked.length },
    { id: 'auditoria', label: 'Auditoría', icon: ShieldCheck, n: audit.length },
  ];

  return (
    <div className="mx-auto max-w-6xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 hw-mono text-2xl font-bold tracking-tight">
            <ShieldAlert className="h-6 w-6 text-neon" /> Respuesta · FortiGate
          </h1>
          <p className="text-sm text-muted-foreground">
            Bloqueo de IPs con confirmación humana · el analista decide, queda registrado
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={reloadAll} disabled={loading}>
          <RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} /> Actualizar
        </Button>
      </div>

      {/* Estado FortiGate */}
      {status && <FortiStatus status={status} />}

      {msg && (
        <div className={`rounded-md border px-3 py-2 text-sm ${msg.k === 'ok'
          ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200'
          : 'border-destructive/40 bg-destructive/10 text-destructive'}`}>
          {msg.t}
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 border-b border-border/60">
        {tabs.map((t) => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors ${
              tab === t.id ? 'border-primary text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground'}`}>
            <t.icon className="h-4 w-4" /> {t.label}
            {typeof t.n === 'number' && <span className="text-xs text-muted-foreground/60">({t.n})</span>}
          </button>
        ))}
      </div>

      {tab === 'incidentes' && (
        <>
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2 rounded-md border border-border/50 bg-background/40 px-3 py-2">
            <p className="text-[11px] text-muted-foreground">
              {threatsOnly
                ? 'Mostrando solo amenazas reales (IOC · ataque/IPS · nivel alto). Se excluyen usuarios de VPN, conectividad benigna y la lista blanca.'
                : 'Mostrando todas las IPs públicas con actividad (aún se excluyen VPN/whitelist, que nunca deben bloquearse).'}
            </p>
            <button
              onClick={() => { setThreatsOnly((v) => !v); }}
              className={`flex shrink-0 items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs ${threatsOnly ? 'border-brand/50 bg-brand/15 text-brand' : 'border-input bg-background text-muted-foreground'}`}
            >
              {threatsOnly ? '◉ Solo amenazas' : '○ Ver todo'}
            </button>
          </div>
          <IncidentsView
            incidents={incidents} isAdmin={isAdmin} expanded={expanded}
            onToggle={(ip) => setExpanded(expanded === ip ? null : ip)}
            onBlock={(ip, ctx) => setModalIp({ ip, context: ctx })}
            onUnblock={doUnblock}
          />
        </>
      )}
      {tab === 'bloqueadas' && <BlockedView blocked={blocked} isAdmin={isAdmin} onUnblock={doUnblock} />}
      {tab === 'auditoria' && <AuditView audit={audit} />}

      {modalIp && (
        <BlockModal
          ip={modalIp.ip}
          context={modalIp.context}
          group={status?.connection.group}
          onConfirm={(m) => confirmBlock(modalIp.ip, m)}
          onCancel={() => setModalIp(null)}
        />
      )}
    </div>
  );
}

function FortiStatus({ status }: { status: ResponseStatus }) {
  const ok = status.connection.ok;
  return (
    <Card>
      <CardContent className="flex flex-wrap items-center gap-4 p-4 text-sm">
        <span className="flex items-center gap-2">
          <Server className="h-4 w-4 text-neon" /> FortiGate
        </span>
        {ok ? (
          <Badge variant="success"><CheckCircle2 className="h-3 w-3" /> Conectado</Badge>
        ) : (
          <Badge variant="danger"><XCircle className="h-3 w-3" /> {status.configured ? 'Sin conexión' : 'No configurado'}</Badge>
        )}
        {ok && (
          <>
            <span className="text-muted-foreground">Grupo: <span className="font-mono text-xs">{status.connection.group}</span></span>
            <span className="text-muted-foreground">{status.connection.count} IPs en la lista</span>
          </>
        )}
        {!ok && status.connection.error && (
          <span className="text-xs text-amber-300">{status.connection.error}</span>
        )}
        <span className="ml-auto text-xs text-muted-foreground/70">Tu IP: {status.adminIp}</span>
      </CardContent>
    </Card>
  );
}

function IncidentsView({ incidents, isAdmin, expanded, onToggle, onBlock, onUnblock }: {
  incidents: Incident[]; isAdmin: boolean; expanded: string | null;
  onToggle: (ip: string) => void; onBlock: (ip: string, ctx?: string) => void; onUnblock: (ip: string) => void;
}) {
  if (incidents.length === 0)
    return <Card><CardContent className="py-8 text-center text-sm text-muted-foreground">Sin IPs sospechosas con IP pública</CardContent></Card>;

  return (
    <div className="space-y-3">
      {incidents.map((i) => {
        const rep = i.reputation;
        const ac = abuseColor(rep?.abuseScore ?? 0);
        return (
          <Card key={i.ip}>
            <CardContent className="p-4">
              <div className="flex flex-wrap items-center gap-3">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono font-semibold">{i.ip}</span>
                    {i.blocked && <Badge variant="danger"><Ban className="h-3 w-3" /> bloqueada</Badge>}
                    {i.ioc && <Badge variant="danger">IOC malicioso</Badge>}
                    {i.attack && <Badge variant="warning">ataque / IPS</Badge>}
                    {i.threat && !i.ioc && !i.attack && <Badge variant="warning">amenaza</Badge>}
                    <span className="rounded-full px-2 py-0.5 text-[11px]" style={{ background: ac.bg, color: ac.fg }}>
                      AbuseIPDB {rep?.abuseScore ?? 0} · {ac.label}
                    </span>
                  </div>
                  <p className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-xs text-muted-foreground">
                    <span className="flex items-center gap-1"><Activity className="h-3 w-3" /> {i.attempts} intentos · nivel {i.severityMax}</span>
                    <span className="flex items-center gap-1"><MapPin className="h-3 w-3" /> {i.country}{i.city ? ` · ${i.city}` : ''}</span>
                    {rep?.isp && <span>{rep.isp}</span>}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <Button variant="ghost" size="sm" onClick={() => onToggle(i.ip)}>
                    <Search className="h-4 w-4" /> Investigar
                  </Button>
                  {isAdmin && (i.blocked ? (
                    <Button variant="outline" size="sm" onClick={() => onUnblock(i.ip)}>
                      <RotateCcw className="h-4 w-4" /> Desbloquear
                    </Button>
                  ) : (
                    <Button variant="destructive" size="sm" onClick={() => onBlock(i.ip, i.ruleDescription)}>
                      <ShieldX className="h-4 w-4" /> Bloquear
                    </Button>
                  ))}
                </div>
              </div>

              {expanded === i.ip && (
                <div className="mt-3 grid gap-3 rounded-md border border-border/50 bg-background/40 p-3 text-xs sm:grid-cols-2">
                  <div><span className="text-muted-foreground">Regla: </span>{i.ruleDescription || '—'}</div>
                  <div><span className="text-muted-foreground">Última vez: </span>{i.lastSeen ? new Date(i.lastSeen).toLocaleString('es-CO') : '—'}</div>
                  <div><span className="text-muted-foreground">Reputación AbuseIPDB: </span>{rep?.configured ? `${rep.abuseScore}/100 · ${rep.totalReports} reportes` : 'no configurado'}</div>
                  <div><span className="text-muted-foreground">Último reporte: </span>{rep?.lastReportedAt ? new Date(rep.lastReportedAt).toLocaleString('es-CO') : '—'}</div>
                  <div><span className="text-muted-foreground">ISP/Dominio: </span>{rep?.isp ?? '—'} {rep?.domain ? `(${rep.domain})` : ''}</div>
                  <div><span className="text-muted-foreground">Geolocalización: </span>{i.lat != null ? `${i.lat.toFixed(3)}, ${i.lon?.toFixed(3)}` : '—'}</div>
                </div>
              )}
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}

function BlockedView({ blocked, isAdmin, onUnblock }: {
  blocked: BlockedItem[]; isAdmin: boolean; onUnblock: (ip: string) => void;
}) {
  return (
    <Card>
      <CardHeader><CardTitle className="text-muted-foreground">IPs bloqueadas por el SOC ({blocked.length})</CardTitle></CardHeader>
      <CardContent>
        {blocked.length === 0 ? (
          <p className="py-6 text-center text-sm text-muted-foreground">No hay IPs bloqueadas por la app</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="border-b border-border/60 text-left text-xs text-muted-foreground">
                <th className="pb-2 pr-4 font-medium">IP</th><th className="pb-2 pr-4 font-medium">Motivo</th>
                <th className="pb-2 pr-4 font-medium">Por</th><th className="pb-2 pr-4 font-medium">Cuándo</th>
                <th className="pb-2 font-medium text-right">Acción</th>
              </tr></thead>
              <tbody>
                {blocked.map((b) => (
                  <tr key={b.ip} className="border-b border-border/30 last:border-0">
                    <td className="py-2.5 pr-4 font-mono">{b.ip}</td>
                    <td className="py-2.5 pr-4 text-muted-foreground">{b.motivo ?? '—'}</td>
                    <td className="py-2.5 pr-4 text-muted-foreground">{b.usuario_email ?? '—'}</td>
                    <td className="py-2.5 pr-4 text-muted-foreground">{b.blocked_at ? new Date(b.blocked_at).toLocaleString('es-CO') : '—'}</td>
                    <td className="py-2.5 text-right">
                      {isAdmin && (
                        <Button variant="outline" size="sm" onClick={() => onUnblock(b.ip)}>
                          <RotateCcw className="h-4 w-4" /> Desbloquear
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function AuditView({ audit }: { audit: AuditRow[] }) {
  const icon = (r: string) =>
    r === 'success' ? <CheckCircle2 className="h-3 w-3" /> : r === 'rejected' ? <AlertTriangle className="h-3 w-3" /> : <XCircle className="h-3 w-3" />;
  const variant = (r: string): 'success' | 'warning' | 'danger' =>
    r === 'success' ? 'success' : r === 'rejected' ? 'warning' : 'danger';
  return (
    <Card>
      <CardHeader><CardTitle className="text-muted-foreground">Auditoría de acciones ({audit.length})</CardTitle></CardHeader>
      <CardContent>
        {audit.length === 0 ? (
          <p className="py-6 text-center text-sm text-muted-foreground">Sin acciones registradas</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="border-b border-border/60 text-left text-xs text-muted-foreground">
                <th className="pb-2 pr-4 font-medium">Fecha</th><th className="pb-2 pr-4 font-medium">Acción</th>
                <th className="pb-2 pr-4 font-medium">IP</th><th className="pb-2 pr-4 font-medium">Motivo</th>
                <th className="pb-2 pr-4 font-medium">Usuario</th><th className="pb-2 font-medium">Resultado</th>
              </tr></thead>
              <tbody>
                {audit.map((a) => (
                  <tr key={a.id} className="border-b border-border/30 last:border-0">
                    <td className="py-2 pr-4 text-muted-foreground">{new Date(a.created_at).toLocaleString('es-CO')}</td>
                    <td className="py-2 pr-4">{a.accion === 'block' ? 'Bloqueo' : 'Desbloqueo'}</td>
                    <td className="py-2 pr-4 font-mono">{a.ip}</td>
                    <td className="py-2 pr-4 text-muted-foreground">{a.motivo ?? (a.detalle ?? '—')}</td>
                    <td className="py-2 pr-4 text-muted-foreground">{a.usuario_email ?? '—'}</td>
                    <td className="py-2"><Badge variant={variant(a.resultado)}>{icon(a.resultado)} {a.resultado}</Badge></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
