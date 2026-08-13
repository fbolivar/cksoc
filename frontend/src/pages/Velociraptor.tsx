/**
 * Velociraptor (DFIR): panel de clientes enrolados y su estado, con acción de
 * lanzar una colección forense por host. Los datos vienen del backend, que habla
 * con la API de Velociraptor vía el helper Python.
 */
import { Fragment, useCallback, useEffect, useRef, useState } from 'react';
import { AxiosError } from 'axios';
import { Crosshair, RefreshCw, Loader2, ExternalLink, ServerCog, MonitorSmartphone, Radio, ChevronRight, ChevronDown } from 'lucide-react';
import { velociraptorApi, type VeloClient, type VeloFlow } from '@/lib/velociraptor';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

// Velociraptor considera "en línea" a un cliente visto hace poco. last_seen_at
// viene en microsegundos desde epoch.
const ONLINE_WINDOW_US = 5 * 60 * 1_000_000; // 5 min
function isOnline(c: VeloClient): boolean {
  if (!c.last_seen_at) return false;
  return Date.now() * 1000 - c.last_seen_at < ONLINE_WINDOW_US;
}
function lastSeen(c: VeloClient): string {
  if (!c.last_seen_at) return '—';
  return new Date(c.last_seen_at / 1000).toLocaleString('es-CO');
}
function isWindows(c: VeloClient): boolean {
  return (c.system || '').toLowerCase().includes('windows');
}
function flowColor(state: string): string {
  const s = (state || '').toUpperCase();
  if (s === 'FINISHED') return '#059669';
  if (s === 'RUNNING') return '#d97706';
  if (s === 'ERROR') return '#dc2626';
  return '#6b7280';
}

export default function Velociraptor() {
  const [clients, setClients] = useState<VeloClient[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [q, setQ] = useState('');
  const [busy, setBusy] = useState<string | null>(null); // host en curso
  const [result, setResult] = useState<Record<string, { url?: string; error?: string }>>({});
  // Colecciones (flows) por cliente: se cargan al expandir la fila.
  const [expanded, setExpanded] = useState<string | null>(null); // client_id expandido
  const [flows, setFlows] = useState<Record<string, { loading: boolean; error?: string; items?: VeloFlow[] }>>({});

  function toggleFlows(clientId: string) {
    if (expanded === clientId) { setExpanded(null); return; }
    setExpanded(clientId);
    if (!flows[clientId]?.items && !flows[clientId]?.loading) {
      setFlows((f) => ({ ...f, [clientId]: { loading: true } }));
      velociraptorApi.flows(clientId)
        .then((items) => setFlows((f) => ({ ...f, [clientId]: { loading: false, items } })))
        .catch((e) => setFlows((f) => ({ ...f, [clientId]: { loading: false, error: (e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudieron cargar las colecciones' } })));
    }
  }

  const seq = useRef(0);
  const load = useCallback(async () => {
    const my = ++seq.current;
    setLoading(true); setError(null);
    try {
      const list = await velociraptorApi.clients();
      if (my === seq.current) setClients(list);
    } catch (e) {
      if (my === seq.current) {
        setClients(null);
        setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo consultar Velociraptor');
      }
    } finally {
      if (my === seq.current) setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  async function investigar(host: string) {
    setBusy(host);
    setResult((r) => ({ ...r, [host]: {} }));
    try {
      const res = await velociraptorApi.collect(host);
      setResult((r) => ({ ...r, [host]: { url: res.url } }));
    } catch (e) {
      setResult((r) => ({ ...r, [host]: { error: (e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo lanzar la colección' } }));
    } finally {
      setBusy(null);
    }
  }

  const total = clients?.length ?? 0;
  const online = clients?.filter(isOnline).length ?? 0;
  const windows = clients?.filter(isWindows).length ?? 0;
  const linux = total - windows;
  const filtered = (clients ?? []).filter((c) =>
    !q || c.host.toLowerCase().includes(q.toLowerCase()) || c.release.toLowerCase().includes(q.toLowerCase())
  );

  return (
    <div className="mx-auto max-w-6xl space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
            <Crosshair className="h-6 w-6 text-neon" /> Velociraptor · DFIR
          </h1>
          <p className="text-sm text-muted-foreground">Clientes forenses enrolados y su estado en vivo</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
          <RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} /> Actualizar
        </Button>
      </div>

      {/* KPIs */}
      <div className="grid gap-3 sm:grid-cols-4">
        <Card><CardContent className="p-4">
          <p className="text-xs text-muted-foreground">Clientes</p>
          <p className="text-2xl font-bold tabular-nums">{total}</p>
        </CardContent></Card>
        <Card><CardContent className="p-4">
          <p className="text-xs text-muted-foreground">En línea</p>
          <p className="text-2xl font-bold tabular-nums text-emerald-600">{online}</p>
        </CardContent></Card>
        <Card><CardContent className="p-4">
          <p className="flex items-center gap-1.5 text-xs text-muted-foreground"><MonitorSmartphone className="h-3.5 w-3.5" /> Windows</p>
          <p className="text-2xl font-bold tabular-nums">{windows}</p>
        </CardContent></Card>
        <Card><CardContent className="p-4">
          <p className="flex items-center gap-1.5 text-xs text-muted-foreground"><ServerCog className="h-3.5 w-3.5" /> Linux</p>
          <p className="text-2xl font-bold tabular-nums">{linux}</p>
        </CardContent></Card>
      </div>

      {error && <Card><CardContent className="p-4 text-sm text-amber-700">{error}</CardContent></Card>}

      <Card>
        <CardContent className="p-0">
          <div className="flex items-center justify-between gap-2 border-b border-border/60 p-3">
            <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filtrar por host o sistema…" className="h-9 max-w-xs" />
            <span className="text-xs text-muted-foreground">{filtered.length} de {total}</span>
          </div>
          {loading && !clients ? (
            <p className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Cargando clientes…</p>
          ) : filtered.length === 0 ? (
            <p className="py-12 text-center text-sm text-muted-foreground">Sin clientes que coincidan.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border/60 text-left text-xs text-muted-foreground">
                    <th className="w-8 px-2 py-2"></th>
                    <th className="px-2 py-2 font-medium">Estado</th>
                    <th className="px-2 py-2 font-medium">Host</th>
                    <th className="px-2 py-2 font-medium">Sistema</th>
                    <th className="px-2 py-2 font-medium">Client ID</th>
                    <th className="px-2 py-2 font-medium">Último visto</th>
                    <th className="px-2 py-2 font-medium text-right">Acción</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((c) => {
                    const on = isOnline(c);
                    const r = result[c.host];
                    const fx = flows[c.client_id];
                    const isOpen = expanded === c.client_id;
                    return (
                      <Fragment key={c.client_id}>
                        <tr className="cursor-pointer border-b border-border/30 last:border-0 hover:bg-secondary/40" onClick={() => toggleFlows(c.client_id)}
                          title="Ver colecciones recientes">
                          <td className="px-2 py-2 text-muted-foreground">{isOpen ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}</td>
                          <td className="whitespace-nowrap px-2 py-2">
                            <span className="inline-flex items-center gap-1.5 text-xs" style={{ color: on ? '#059669' : '#9ca3af' }}>
                              <Radio className="h-3.5 w-3.5" /> {on ? 'En línea' : 'Desconectado'}
                            </span>
                          </td>
                          <td className="px-2 py-2 font-medium">{c.host}</td>
                          <td className="px-2 py-2 text-xs text-muted-foreground">{c.release || c.system}</td>
                          <td className="px-2 py-2 font-mono text-[11px] text-muted-foreground">{c.client_id}</td>
                          <td className="whitespace-nowrap px-2 py-2 text-xs text-muted-foreground">{lastSeen(c)}</td>
                          <td className="px-2 py-2 text-right" onClick={(e) => e.stopPropagation()}>
                            <div className="flex flex-col items-end gap-1">
                              <Button size="sm" variant="outline" onClick={() => void investigar(c.host)} disabled={busy === c.host}
                                title={`Lanza una colección forense en ${c.host}`}>
                                {busy === c.host ? <Loader2 className="h-4 w-4 animate-spin" /> : <Crosshair className="h-4 w-4" />} Investigar
                              </Button>
                              {r && (r.error ? (
                                <span className="text-[11px] text-destructive">{r.error}</span>
                              ) : r.url ? (
                                <a href={r.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-[11px] text-neon hover:underline">
                                  <ExternalLink className="h-3 w-3" /> ver evidencia
                                </a>
                              ) : null)}
                            </div>
                          </td>
                        </tr>
                        {isOpen && (
                          <tr className="border-b border-border/30 bg-secondary/20">
                            <td colSpan={7} className="px-6 py-3">
                              <p className="mb-2 text-xs font-semibold text-muted-foreground">Colecciones recientes</p>
                              {fx?.loading ? (
                                <p className="flex items-center gap-2 py-3 text-xs text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Cargando…</p>
                              ) : fx?.error ? (
                                <p className="py-2 text-xs text-amber-700">{fx.error}</p>
                              ) : !fx?.items || fx.items.length === 0 ? (
                                <p className="py-2 text-xs text-muted-foreground">Este cliente no tiene colecciones registradas.</p>
                              ) : (
                                <table className="w-full text-xs">
                                  <thead>
                                    <tr className="text-left text-[11px] text-muted-foreground/80">
                                      <th className="py-1 pr-3 font-medium">Artefacto</th>
                                      <th className="py-1 pr-3 font-medium">Estado</th>
                                      <th className="py-1 pr-3 font-medium">Fecha</th>
                                      <th className="py-1 pr-3 font-medium">Filas</th>
                                      <th className="py-1 pr-3 font-medium">Lanzado por</th>
                                      <th className="py-1 pr-3 font-medium"></th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {fx.items.map((fl) => (
                                      <tr key={fl.flow_id} className="border-t border-border/30">
                                        <td className="py-1.5 pr-3">{fl.artifacts || '—'}</td>
                                        <td className="py-1.5 pr-3">
                                          <span style={{ color: flowColor(fl.state) }}>{fl.state}</span>
                                        </td>
                                        <td className="whitespace-nowrap py-1.5 pr-3 text-muted-foreground">{fl.created ? new Date(fl.created).toLocaleString('es-CO') : '—'}</td>
                                        <td className="py-1.5 pr-3 tabular-nums text-muted-foreground">{fl.rows ?? 0}</td>
                                        <td className="py-1.5 pr-3 text-muted-foreground">{fl.creator || '—'}</td>
                                        <td className="py-1.5 pr-3 text-right">
                                          <a href={fl.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-neon hover:underline">
                                            <ExternalLink className="h-3 w-3" /> ver
                                          </a>
                                        </td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              )}
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
