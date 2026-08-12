/**
 * IT Hygiene: inventario de los endpoints. Sistema/hardware, puertos a la
 * escucha (superficie de ataque), software, usuarios (cuentas de riesgo) y parches.
 */
import { useEffect, useState } from 'react';
import { AxiosError } from 'axios';
import { Activity, RefreshCw, Loader2, Server, Network, Package, Users, ShieldCheck } from 'lucide-react';
import {
  hygieneApi, type Summary, type PortRow, type SoftwareRow, type UsersData, type HotfixRow,
} from '@/lib/hygiene';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

type Tab = 'sistema' | 'puertos' | 'software' | 'usuarios' | 'parches';
const TABS: { id: Tab; label: string }[] = [
  { id: 'sistema', label: 'Sistema' },
  { id: 'puertos', label: 'Puertos' },
  { id: 'software', label: 'Software' },
  { id: 'usuarios', label: 'Usuarios' },
  { id: 'parches', label: 'Parches' },
];

const KPI_DEFS: { key: string; label: string }[] = [
  { key: 'hosts', label: 'Activos' },
  { key: 'packages', label: 'Software' },
  { key: 'listening', label: 'Puertos a la escucha' },
  { key: 'processes', label: 'Procesos' },
  { key: 'users', label: 'Usuarios' },
  { key: 'hotfixes', label: 'Parches' },
];

export default function Hygiene() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [tab, setTab] = useState<Tab>('sistema');
  const [ports, setPorts] = useState<PortRow[] | null>(null);
  const [software, setSoftware] = useState<SoftwareRow[] | null>(null);
  const [users, setUsers] = useState<UsersData | null>(null);
  const [hotfixes, setHotfixes] = useState<HotfixRow[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function loadSummary() {
    setLoading(true); setError(null);
    try { setSummary(await hygieneApi.summary()); }
    catch (e) { setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo cargar el inventario'); }
    finally { setLoading(false); }
  }
  useEffect(() => { loadSummary(); }, []);

  // Carga perezosa por pestaña (las guardas !ports/... evitan recargas)
  useEffect(() => {
    if (tab === 'puertos' && !ports) hygieneApi.ports().then(setPorts).catch(() => setPorts([]));
    if (tab === 'software' && !software) hygieneApi.software().then(setSoftware).catch(() => setSoftware([]));
    if (tab === 'usuarios' && !users) hygieneApi.users().then(setUsers).catch(() => setUsers({ porAgente: [], riesgo: [] }));
    if (tab === 'parches' && !hotfixes) hygieneApi.hotfixes().then(setHotfixes).catch(() => setHotfixes([]));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab]);

  const maxHtf = Math.max(1, ...(hotfixes ?? []).map((h) => h.count));

  return (
    <div className="mx-auto max-w-7xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
            <Activity className="h-6 w-6 text-neon" /> IT Hygiene
          </h1>
          <p className="text-sm text-muted-foreground">
            Inventario y superficie de ataque de los endpoints monitoreados
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={loadSummary} disabled={loading}>
          <RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} /> Actualizar
        </Button>
      </div>

      {error && <Card><CardContent className="p-4 text-sm text-amber-700">{error}</CardContent></Card>}

      {loading && !summary ? (
        <p className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" /> Cargando inventario…
        </p>
      ) : summary && (
        <>
          {/* KPIs */}
          <div className="grid gap-3 grid-cols-2 sm:grid-cols-3 lg:grid-cols-6">
            {KPI_DEFS.map((k) => (
              <Card key={k.key}><CardContent className="p-3">
                <p className="text-[11px] text-muted-foreground">{k.label}</p>
                <p className="mt-0.5 text-xl font-semibold tabular-nums">{(summary.kpis[k.key] ?? 0).toLocaleString('es-CO')}</p>
              </CardContent></Card>
            ))}
          </div>

          {/* Pestañas */}
          <div className="flex flex-wrap gap-1 border-b border-border/60">
            {TABS.map((t) => (
              <button key={t.id} onClick={() => setTab(t.id)}
                className={`px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors ${
                  tab === t.id ? 'border-primary text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground'
                }`}>
                {t.label}
              </button>
            ))}
          </div>

          {/* Sistema */}
          {tab === 'sistema' && (
            <Card><CardContent className="overflow-x-auto p-0">
              <table className="w-full text-sm">
                <thead><tr className="border-b border-border/60 text-left text-xs text-muted-foreground">
                  <th className="p-3 font-medium">Activo</th><th className="p-3 font-medium">Sistema operativo</th>
                  <th className="p-3 font-medium">CPU</th><th className="p-3 font-medium">RAM</th>
                  <th className="p-3 font-medium text-right">Software</th><th className="p-3 font-medium text-right">Puertos</th>
                  <th className="p-3 font-medium text-right">Usuarios</th><th className="p-3 font-medium text-right">Parches</th>
                </tr></thead>
                <tbody>
                  {summary.hosts.map((h) => (
                    <tr key={h.agent} className="border-b border-border/30 last:border-0">
                      <td className="p-3 font-mono text-xs"><span className="flex items-center gap-1.5"><Server className="h-3.5 w-3.5 text-muted-foreground" />{h.hostname}</span></td>
                      <td className="p-3 text-xs text-muted-foreground">{h.os} <span className="text-muted-foreground/50">({h.arch})</span></td>
                      <td className="p-3 text-xs text-muted-foreground">{h.cores} núcleos<span className="block text-[10px] text-muted-foreground/50">{h.cpu}</span></td>
                      <td className="p-3 text-xs text-muted-foreground tabular-nums">{h.ramGB} GB</td>
                      <td className="p-3 text-right tabular-nums">{h.packages}</td>
                      <td className="p-3 text-right tabular-nums">{h.ports}</td>
                      <td className="p-3 text-right tabular-nums">{h.users.toLocaleString('es-CO')}</td>
                      <td className="p-3 text-right tabular-nums">{h.hotfixes}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </CardContent></Card>
          )}

          {/* Puertos */}
          {tab === 'puertos' && (
            <Card>
              <CardHeader><CardTitle className="flex items-center gap-2 text-muted-foreground">
                <Network className="h-4 w-4" /> Puertos a la escucha — superficie de ataque {ports && `(${ports.length})`}
              </CardTitle></CardHeader>
              <CardContent>
                {!ports ? <Loading /> : (
                  <div className="max-h-[560px] overflow-auto">
                    <table className="w-full text-sm">
                      <thead className="sticky top-0 bg-card"><tr className="border-b border-border/60 text-left text-xs text-muted-foreground">
                        <th className="py-2 pr-3 font-medium">Activo</th><th className="py-2 pr-3 font-medium">Proto</th>
                        <th className="py-2 pr-3 font-medium">Dirección : Puerto</th><th className="py-2 font-medium">Proceso</th>
                      </tr></thead>
                      <tbody>
                        {ports.map((p, i) => (
                          <tr key={`${p.agent}-${p.transport}-${p.ip}-${p.port}-${i}`} className="border-b border-border/20 last:border-0">
                            <td className="py-1.5 pr-3 font-mono text-[11px] text-muted-foreground">{p.agent}</td>
                            <td className="py-1.5 pr-3 text-[11px] uppercase text-muted-foreground">{p.transport}</td>
                            <td className="py-1.5 pr-3 font-mono text-xs">{p.ip}:<b className="text-neon">{p.port}</b></td>
                            <td className="py-1.5 text-xs text-muted-foreground">{p.process}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* Software */}
          {tab === 'software' && (
            <Card>
              <CardHeader><CardTitle className="flex items-center gap-2 text-muted-foreground">
                <Package className="h-4 w-4" /> Software instalado {software && `(${software.length})`}
              </CardTitle></CardHeader>
              <CardContent>
                {!software ? <Loading /> : (
                  <div className="grid gap-2 md:grid-cols-2">
                    {software.map((s, i) => (
                      <div key={`${s.name}-${i}`} className="flex items-center gap-3 rounded-md border border-border/40 px-3 py-2">
                        <span className="min-w-[2rem] rounded bg-secondary px-1.5 py-0.5 text-center text-[10px] text-muted-foreground" title="activos con este software">{s.hosts}</span>
                        <div className="min-w-0 flex-1">
                          <p className="truncate text-sm">{s.name}</p>
                          {s.vendor && <p className="truncate text-[10px] text-muted-foreground">{s.vendor}</p>}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* Usuarios */}
          {tab === 'usuarios' && (
            <div className="grid gap-4 lg:grid-cols-2">
              <Card>
                <CardHeader><CardTitle className="flex items-center gap-2 text-muted-foreground"><Users className="h-4 w-4" /> Cuentas por activo</CardTitle></CardHeader>
                <CardContent className="space-y-2">
                  {!users ? <Loading /> : users.porAgente.map((a) => (
                    <div key={a.agent} className="flex items-center justify-between text-sm">
                      <span className="flex items-center gap-1.5 font-mono text-xs"><Server className="h-3.5 w-3.5 text-muted-foreground" />{a.agent}</span>
                      <span className="tabular-nums font-medium">{a.count.toLocaleString('es-CO')}</span>
                    </div>
                  ))}
                </CardContent>
              </Card>
              <Card>
                <CardHeader><CardTitle className="text-muted-foreground">Cuentas de riesgo (ocultas / con fallos de auth)</CardTitle></CardHeader>
                <CardContent>
                  {!users ? <Loading /> : users.riesgo.length === 0 ? (
                    <p className="flex items-center gap-2 py-4 text-sm text-emerald-400">
                      <ShieldCheck className="h-4 w-4" /> Sin cuentas ocultas ni con fallos de autenticación registrados.
                    </p>
                  ) : (
                    <div className="space-y-1.5">
                      {users.riesgo.map((u, i) => (
                        <div key={`${u.agent}-${u.name}-${i}`} className="flex items-center gap-2 text-sm">
                          <span className="font-mono text-xs">{u.name}</span>
                          {u.hidden && <span className="rounded bg-red-500/15 px-1.5 text-[10px] text-red-400">oculta</span>}
                          {u.authFailures > 0 && <span className="rounded bg-amber-500/15 px-1.5 text-[10px] text-amber-400">{u.authFailures} fallos</span>}
                          <span className="ml-auto text-[10px] text-muted-foreground">{u.agent}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          )}

          {/* Parches */}
          {tab === 'parches' && (
            <Card>
              <CardHeader><CardTitle className="text-muted-foreground">Nivel de parches por activo</CardTitle></CardHeader>
              <CardContent className="space-y-3">
                {!hotfixes ? <Loading /> : hotfixes.map((h) => (
                  <div key={h.agent}>
                    <div className="mb-1 flex items-center justify-between text-sm">
                      <span className="flex items-center gap-1.5 font-mono text-xs"><Server className="h-3.5 w-3.5 text-muted-foreground" />{h.agent}</span>
                      <span className="tabular-nums text-muted-foreground">{h.count} parches · <span className="text-muted-foreground/60">últimos: {h.recientes.join(', ')}</span></span>
                    </div>
                    <div className="h-2 w-full overflow-hidden rounded-full bg-secondary">
                      <div className="h-full" style={{ width: `${(h.count / maxHtf) * 100}%`, background: h.count < maxHtf * 0.5 ? '#f97316' : '#22c55e' }} />
                    </div>
                  </div>
                ))}
                {hotfixes && <p className="pt-1 text-[11px] text-muted-foreground/70">Una barra naranja indica un activo con notablemente menos parches que el resto (posible rezago de actualizaciones).</p>}
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  );
}

function Loading() {
  return <p className="flex items-center gap-2 py-6 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Cargando…</p>;
}
