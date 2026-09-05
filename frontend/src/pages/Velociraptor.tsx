/**
 * Velociraptor (DFIR): panel de clientes enrolados y su estado. Permite:
 *  - Ver colecciones recientes por cliente (fila expandible).
 *  - Lanzar una colección eligiendo el artefacto (modal con catálogo).
 *  - Ver el detalle de resultados de una colección (modal con tablas por fuente).
 * Los datos vienen del backend, que habla con la API de Velociraptor (helper Python).
 */
import { Fragment, useCallback, useEffect, useRef, useState } from 'react';
import { AxiosError } from 'axios';
import {
  Crosshair, RefreshCw, Loader2, ExternalLink, ServerCog, MonitorSmartphone, Radio,
  ChevronRight, ChevronDown, X, Search, Play, CheckCircle2, Table2, WifiOff, Wifi, Stethoscope, Lightbulb,
} from 'lucide-react';
import {
  velociraptorApi, type VeloClient, type VeloFlow, type VeloArtifact, type VeloResultSource, type EndpointAction, type VeloRec,
} from '@/lib/velociraptor';
import { useAuth } from '@/lib/auth';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

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
function cellText(v: unknown): string {
  if (v === null || v === undefined) return '';
  if (typeof v === 'object') return JSON.stringify(v);
  return String(v);
}

export default function Velociraptor() {
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';
  const [clients, setClients] = useState<VeloClient[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [q, setQ] = useState('');
  const [expanded, setExpanded] = useState<string | null>(null);
  const [flows, setFlows] = useState<Record<string, { loading: boolean; error?: string; items?: VeloFlow[] }>>({});
  // Contención (aislar/liberar/triage) por host.
  const [contain, setContain] = useState<Record<string, { busy?: EndpointAction; msg?: string; err?: string }>>({});
  // Modales
  const [collectFor, setCollectFor] = useState<VeloClient | null>(null);
  const [resultsFor, setResultsFor] = useState<{ client: VeloClient; flow: VeloFlow } | null>(null);
  // Recomendaciones (hosts de alto riesgo).
  const [recs, setRecs] = useState<VeloRec[]>([]);
  const [recBusy, setRecBusy] = useState<string | null>(null);
  const [recMsg, setRecMsg] = useState<{ host: string; url?: string; error?: string } | null>(null);

  async function collectRec(host: string) {
    setRecBusy(host); setRecMsg(null);
    try { const r = await velociraptorApi.collect(host); setRecMsg({ host, url: r.url }); }
    catch (e) { setRecMsg({ host, error: (e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo lanzar la colección' }); }
    finally { setRecBusy(null); }
  }

  async function endpointAction(c: VeloClient, action: EndpointAction) {
    if (action === 'isolate' && !confirm(`¿AISLAR ${c.host} de la red? Cortará todo su tráfico salvo Velociraptor (contención). Podrás liberarlo después.`)) return;
    setContain((s) => ({ ...s, [c.host]: { busy: action } }));
    try {
      await velociraptorApi.action(c.host, action);
      const msg = action === 'isolate' ? 'aislamiento enviado' : action === 'release' ? 'liberación enviada' : 'triage lanzado';
      setContain((s) => ({ ...s, [c.host]: { msg } }));
      if (action !== 'triage') setTimeout(() => void load(), 4000); // refresca el badge de aislado
    } catch (e) {
      setContain((s) => ({ ...s, [c.host]: { err: (e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo ejecutar la acción' } }));
    }
  }

  const loadFlows = useCallback((clientId: string, force = false) => {
    if (!force && (flows[clientId]?.items || flows[clientId]?.loading)) return;
    setFlows((f) => ({ ...f, [clientId]: { loading: true } }));
    velociraptorApi.flows(clientId)
      .then((items) => setFlows((f) => ({ ...f, [clientId]: { loading: false, items } })))
      .catch((e) => setFlows((f) => ({ ...f, [clientId]: { loading: false, error: (e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudieron cargar las colecciones' } })));
  }, [flows]);

  function toggleFlows(clientId: string) {
    if (expanded === clientId) { setExpanded(null); return; }
    setExpanded(clientId);
    loadFlows(clientId);
  }

  const seq = useRef(0);
  const load = useCallback(async () => {
    const my = ++seq.current;
    setLoading(true); setError(null);
    try {
      const list = await velociraptorApi.clients();
      if (my === seq.current) setClients(list);
      velociraptorApi.recommendations().then((d) => { if (my === seq.current) setRecs(d.items ?? []); }).catch(() => undefined);
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
          <h1 className="flex items-center gap-2 hw-mono text-2xl font-bold tracking-tight">
            <Crosshair className="h-6 w-6 text-neon" /> Velociraptor · DFIR
          </h1>
          <p className="text-sm text-muted-foreground">Clientes forenses, colecciones y resultados</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
          <RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} /> Actualizar
        </Button>
      </div>

      <div className="grid gap-3 sm:grid-cols-4">
        <Card><CardContent className="p-4"><p className="text-xs text-muted-foreground">Clientes</p><p className="text-2xl font-bold tabular-nums">{total}</p></CardContent></Card>
        <Card><CardContent className="p-4"><p className="text-xs text-muted-foreground">En línea</p><p className="text-2xl font-bold tabular-nums text-emerald-600">{online}</p></CardContent></Card>
        <Card><CardContent className="p-4"><p className="flex items-center gap-1.5 text-xs text-muted-foreground"><MonitorSmartphone className="h-3.5 w-3.5" /> Windows</p><p className="text-2xl font-bold tabular-nums">{windows}</p></CardContent></Card>
        <Card><CardContent className="p-4"><p className="flex items-center gap-1.5 text-xs text-muted-foreground"><ServerCog className="h-3.5 w-3.5" /> Linux</p><p className="text-2xl font-bold tabular-nums">{linux}</p></CardContent></Card>
      </div>

      {error && <Card><CardContent className="p-4 text-sm text-amber-700">{error}</CardContent></Card>}

      {/* Recomendaciones · Hosts de alto riesgo (triage forense) */}
      {recs.length > 0 && (
        <Card className="border-amber-500/40"><CardContent className="p-4">
          <p className="mb-2 flex items-center gap-2 text-sm font-semibold"><Lightbulb className="h-4 w-4 text-amber-500" /> Recomendaciones · Hosts de alto riesgo (triage forense)</p>
          <div className="space-y-2">
            {recs.map((r) => {
              const col = r.severity === 'alta' ? '#dc2626' : '#d97706';
              return (
                <div key={r.host} className="hw-clip flex flex-wrap items-center justify-between gap-2 border border-border p-2.5" style={{ borderLeft: `3px solid ${col}` }}>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="hw-mono rounded px-1.5 py-0.5 text-[10px] font-bold" style={{ color: col, background: `${col}22` }}>{r.band.toUpperCase()} · {r.risk}</span>
                      <span className="truncate text-xs font-semibold">{r.host}</span>
                      {r.hasVelo && (r.veloOnline
                        ? <span className="inline-flex items-center gap-0.5 text-[10px] text-emerald-600" title="Agente Velociraptor activo en las últimas 24h"><Wifi className="h-3 w-3" /> Velo activo</span>
                        : <span className="inline-flex items-center gap-0.5 text-[10px] text-rose-600"><WifiOff className="h-3 w-3" /> Velo sin señal{r.veloLastSeenH != null ? ` ${r.veloLastSeenH}h` : ''}</span>)}
                      {r.status !== 'active' && <span className="text-[10px] text-muted-foreground/70">Wazuh off</span>}
                      {r.isolated && <span className="text-[10px] text-amber-600">aislado</span>}
                    </div>
                    <p className="mt-1 text-[11px] text-muted-foreground">{r.reason}</p>
                    <div className="mt-0.5 text-[10px] text-muted-foreground/70">{r.ip || '—'} · {r.os}</div>
                  </div>
                  {recMsg?.host === r.host && recMsg.url ? (
                    <a href={recMsg.url} target="_blank" rel="noreferrer" className="flex shrink-0 items-center gap-1 text-[11px] text-emerald-600"><CheckCircle2 className="h-3.5 w-3.5" /> Colección lanzada <ExternalLink className="h-3 w-3" /></a>
                  ) : r.triageable ? (
                    <button disabled={recBusy === r.host} onClick={() => collectRec(r.host)}
                      className="flex shrink-0 items-center gap-1 rounded px-2.5 py-1 text-[11px] text-white disabled:opacity-50" style={{ background: 'hsl(var(--primary))' }}>
                      {recBusy === r.host ? '…' : <><Stethoscope className="h-3 w-3" /> Investigar</>}
                    </button>
                  ) : r.hasVelo ? (
                    <span className="shrink-0 text-right text-[10px] text-rose-600/80">Velo desconectado{r.veloLastSeenH != null ? ` (${r.veloLastSeenH}h)` : ''}<br />no responderá al triage</span>
                  ) : (
                    <span className="shrink-0 text-[10px] text-muted-foreground/70">sin cliente Velociraptor</span>
                  )}
                </div>
              );
            })}
          </div>
          {recMsg?.error && <p className="mt-2 text-xs text-rose-600">{recMsg.error}</p>}
          <p className="mt-2 text-[10px] text-muted-foreground/60">Riesgo del radar (vulnerabilidades + alertas 24h + estado). «Investigar» lanza una colección forense (triage) en el host.</p>
        </CardContent></Card>
      )}

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
                    const fx = flows[c.client_id];
                    const isOpen = expanded === c.client_id;
                    const on = isOnline(c);
                    return (
                      <Fragment key={c.client_id}>
                        <tr className="cursor-pointer border-b border-border/30 last:border-0 hover:bg-secondary/40" onClick={() => toggleFlows(c.client_id)} title="Ver colecciones recientes">
                          <td className="px-2 py-2 text-muted-foreground">{isOpen ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}</td>
                          <td className="whitespace-nowrap px-2 py-2">
                            <span className="inline-flex items-center gap-1.5 text-xs" style={{ color: on ? '#059669' : '#9ca3af' }}>
                              <Radio className="h-3.5 w-3.5" /> {on ? 'En línea' : 'Desconectado'}
                            </span>
                          </td>
                          <td className="px-2 py-2 font-medium">
                            {c.host}
                            {c.isolated && <span className="ml-2 inline-flex items-center gap-1 rounded bg-rose-500/15 px-1.5 py-0.5 text-[10px] font-semibold text-rose-600"><WifiOff className="h-3 w-3" /> aislado</span>}
                          </td>
                          <td className="px-2 py-2 text-xs text-muted-foreground">{c.release || c.system}</td>
                          <td className="px-2 py-2 font-mono text-[11px] text-muted-foreground">{c.client_id}</td>
                          <td className="whitespace-nowrap px-2 py-2 text-xs text-muted-foreground">{lastSeen(c)}</td>
                          <td className="px-2 py-2 text-right" onClick={(e) => e.stopPropagation()}>
                            <div className="flex flex-col items-end gap-1">
                              <div className="flex items-center gap-1.5">
                                <Button size="sm" variant="outline" onClick={() => setCollectFor(c)} title={`Lanzar una colección en ${c.host}`}>
                                  <Crosshair className="h-4 w-4" /> Recolectar
                                </Button>
                                <Button size="sm" variant="outline" onClick={() => void endpointAction(c, 'triage')} disabled={contain[c.host]?.busy === 'triage'} title="Triage rápido (procesos + red + info)">
                                  {contain[c.host]?.busy === 'triage' ? <Loader2 className="h-4 w-4 animate-spin" /> : <Stethoscope className="h-4 w-4" />} Triage
                                </Button>
                                {isAdmin && (c.isolated ? (
                                  <Button size="sm" variant="outline" onClick={() => void endpointAction(c, 'release')} disabled={contain[c.host]?.busy === 'release'} title="Liberar el host de la cuarentena">
                                    {contain[c.host]?.busy === 'release' ? <Loader2 className="h-4 w-4 animate-spin" /> : <Wifi className="h-4 w-4" />} Liberar
                                  </Button>
                                ) : (
                                  <Button size="sm" variant="destructive" onClick={() => void endpointAction(c, 'isolate')} disabled={contain[c.host]?.busy === 'isolate'} title="Aislar el host de la red (contención)">
                                    {contain[c.host]?.busy === 'isolate' ? <Loader2 className="h-4 w-4 animate-spin" /> : <WifiOff className="h-4 w-4" />} Aislar
                                  </Button>
                                ))}
                              </div>
                              {contain[c.host]?.msg && <span className="text-[11px] text-emerald-600">{contain[c.host]?.msg}</span>}
                              {contain[c.host]?.err && <span className="text-[11px] text-destructive">{contain[c.host]?.err}</span>}
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
                                      <th className="py-1 pr-3 font-medium text-right">Resultados</th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {fx.items.map((fl) => (
                                      <tr key={fl.flow_id} className="border-t border-border/30">
                                        <td className="py-1.5 pr-3">{fl.artifacts || '—'}</td>
                                        <td className="py-1.5 pr-3"><span style={{ color: flowColor(fl.state) }}>{fl.state}</span></td>
                                        <td className="whitespace-nowrap py-1.5 pr-3 text-muted-foreground">{fl.created ? new Date(fl.created).toLocaleString('es-CO') : '—'}</td>
                                        <td className="py-1.5 pr-3 tabular-nums text-muted-foreground">{fl.rows ?? 0}</td>
                                        <td className="py-1.5 pr-3 text-muted-foreground">{fl.creator || '—'}</td>
                                        <td className="py-1.5 pr-3 text-right">
                                          <div className="flex items-center justify-end gap-2">
                                            <button onClick={() => setResultsFor({ client: c, flow: fl })} disabled={!fl.rows}
                                              className="inline-flex items-center gap-1 text-neon hover:underline disabled:cursor-not-allowed disabled:text-muted-foreground/40" title="Ver resultados en HexWatch">
                                              <Table2 className="h-3 w-3" /> ver detalle
                                            </button>
                                            <a href={fl.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-muted-foreground hover:text-foreground" title="Abrir en Velociraptor">
                                              <ExternalLink className="h-3 w-3" />
                                            </a>
                                          </div>
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

      {collectFor && (
        <CollectModal client={collectFor} onClose={() => setCollectFor(null)}
          onLaunched={(clientId) => { loadFlows(clientId, true); }} />
      )}
      {resultsFor && (
        <ResultsModal client={resultsFor.client} flow={resultsFor.flow} onClose={() => setResultsFor(null)} />
      )}
    </div>
  );
}

/** Modal para lanzar una colección eligiendo el artefacto del catálogo. */
function CollectModal({ client, onClose, onLaunched }: { client: VeloClient; onClose: () => void; onLaunched: (clientId: string) => void }) {
  const [catalog, setCatalog] = useState<VeloArtifact[] | null>(null);
  const [catErr, setCatErr] = useState<string | null>(null);
  const [q, setQ] = useState('');
  const [selected, setSelected] = useState('Generic.Client.Info');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ url?: string; error?: string } | null>(null);

  useEffect(() => {
    velociraptorApi.artifacts()
      .then(setCatalog)
      .catch((e) => setCatErr((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo cargar el catálogo'));
  }, []);

  const list = (catalog ?? []).filter((a) =>
    !q || a.name.toLowerCase().includes(q.toLowerCase()) || a.description.toLowerCase().includes(q.toLowerCase())
  ).slice(0, 200);

  async function launch() {
    setBusy(true); setResult(null);
    try {
      const res = await velociraptorApi.collect(client.host, selected);
      setResult({ url: res.url });
      onLaunched(client.client_id);
    } catch (e) {
      setResult({ error: (e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo lanzar la colección' });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div className="flex max-h-[85vh] w-full max-w-2xl flex-col rounded-lg border border-border/70 bg-card shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between border-b border-border/60 px-5 py-3">
          <h3 className="font-semibold">Recolectar en <span className="font-mono text-sm">{client.host}</span></h3>
          <Button variant="ghost" size="icon" onClick={onClose}><X className="h-4 w-4" /></Button>
        </div>
        <div className="space-y-3 overflow-hidden p-5">
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Buscar artefacto (p. ej. Pslist, Users, Netstat)…" className="h-9 pl-8" />
          </div>
          <p className="text-[11px] text-muted-foreground">Seleccionado: <span className="font-mono text-foreground">{selected}</span></p>
          <div className="max-h-[45vh] overflow-y-auto rounded-md border border-border/50">
            {catErr ? (
              <p className="p-4 text-sm text-amber-700">{catErr}</p>
            ) : !catalog ? (
              <p className="flex items-center gap-2 p-4 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Cargando catálogo…</p>
            ) : list.length === 0 ? (
              <p className="p-4 text-sm text-muted-foreground">Sin artefactos que coincidan.</p>
            ) : (
              list.map((a) => (
                <button key={a.name} onClick={() => setSelected(a.name)}
                  className={`block w-full border-b border-border/30 px-3 py-2 text-left last:border-0 hover:bg-secondary/50 ${selected === a.name ? 'bg-secondary' : ''}`}>
                  <p className="font-mono text-xs">{a.name}</p>
                  {a.description && <p className="truncate text-[11px] text-muted-foreground">{a.description}</p>}
                </button>
              ))
            )}
          </div>
        </div>
        <div className="flex items-center justify-between gap-2 border-t border-border/60 px-5 py-3">
          <div className="text-[11px]">
            {result && (result.error ? (
              <span className="text-destructive">{result.error}</span>
            ) : result.url ? (
              <a href={result.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-emerald-600 hover:underline">
                <CheckCircle2 className="h-3.5 w-3.5" /> Colección lanzada · ver en Velociraptor
              </a>
            ) : null)}
          </div>
          <div className="flex gap-2">
            <Button variant="outline" onClick={onClose} disabled={busy}>Cerrar</Button>
            <Button onClick={() => void launch()} disabled={busy || !selected}>
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />} Lanzar colección
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

/** Modal con el detalle de resultados de una colección (tablas por fuente). */
function ResultsModal({ client, flow, onClose }: { client: VeloClient; flow: VeloFlow; onClose: () => void }) {
  const [sources, setSources] = useState<VeloResultSource[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    velociraptorApi.flowResults(client.client_id, flow.flow_id)
      .then(setSources)
      .catch((e) => setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudieron cargar los resultados'));
  }, [client.client_id, flow.flow_id]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div className="flex max-h-[88vh] w-full max-w-5xl flex-col rounded-lg border border-border/70 bg-card shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between border-b border-border/60 px-5 py-3">
          <div>
            <h3 className="font-semibold">Resultados · {flow.artifacts || flow.flow_id}</h3>
            <p className="text-xs text-muted-foreground">{client.host} · <span className="font-mono">{flow.flow_id}</span></p>
          </div>
          <div className="flex items-center gap-2">
            <a href={flow.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-neon hover:underline"><ExternalLink className="h-3.5 w-3.5" /> abrir en Velociraptor</a>
            <Button variant="ghost" size="icon" onClick={onClose}><X className="h-4 w-4" /></Button>
          </div>
        </div>
        <div className="space-y-5 overflow-auto p-5">
          {error ? (
            <p className="text-sm text-amber-700">{error}</p>
          ) : !sources ? (
            <p className="flex items-center gap-2 py-8 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Cargando resultados…</p>
          ) : sources.length === 0 ? (
            <p className="py-8 text-center text-sm text-muted-foreground">Esta colección no tiene filas de resultados.</p>
          ) : (
            sources.map((src) => (
              <div key={src.artifact}>
                <p className="mb-2 text-sm font-semibold">{src.artifact} <span className="text-xs font-normal text-muted-foreground">· {src.count} fila(s){src.count >= 200 ? '+ (mostrando 200)' : ''}</span></p>
                <div className="overflow-x-auto rounded-md border border-border/50">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-border/50 bg-secondary/30 text-left text-[11px] text-muted-foreground">
                        {src.columns.map((col) => <th key={col} className="whitespace-nowrap px-2 py-1.5 font-medium">{col}</th>)}
                      </tr>
                    </thead>
                    <tbody>
                      {src.rows.map((row, i) => (
                        <tr key={i} className="border-b border-border/20 last:border-0 hover:bg-secondary/20">
                          {src.columns.map((col) => (
                            <td key={col} className="max-w-xs truncate px-2 py-1.5 font-mono text-[11px]" title={cellText(row[col])}>{cellText(row[col])}</td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
