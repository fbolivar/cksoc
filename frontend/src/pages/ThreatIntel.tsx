/**
 * Threat Intelligence: catálogo de IOCs (feeds públicos + manuales) y, lo más
 * accionable, las COINCIDENCIAS de IPs maliciosas conocidas contra las alertas
 * (Wazuh + SonicWall) de las últimas 24 h, con bloqueo directo en el SonicWall.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { AxiosError } from 'axios';
import {
  Radar, Loader2, Plus, Trash2, X, Ban, ExternalLink, ShieldAlert, ShieldCheck, Rss,
} from 'lucide-react';
import { threatIntelApi, type Ioc, type IocMatch, type FeedStatus, type IocType } from '@/lib/threatintel';
import { responseApi } from '@/lib/response';
import { useAuth } from '@/lib/auth';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

const TYPES: IocType[] = ['ip', 'domain', 'url', 'md5', 'sha1', 'sha256'];

export default function ThreatIntel() {
  const { user } = useAuth();
  const canManage = user?.role === 'admin' || user?.role === 'analista';

  const [summary, setSummary] = useState<{ total: number; byType: Record<string, number>; feeds: FeedStatus[] } | null>(null);
  const [matches, setMatches] = useState<IocMatch[] | null>(null);
  const [iocs, setIocs] = useState<Ioc[] | null>(null);
  const [typeF, setTypeF] = useState('');
  const [q, setQ] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [showAdd, setShowAdd] = useState(false);
  const [blocked, setBlocked] = useState<Record<string, { ok?: boolean; error?: string; busy?: boolean; permanent?: boolean }>>({});

  const loadAll = useCallback(async () => {
    setError(null);
    try {
      const [s, m] = await Promise.all([threatIntelApi.summary(), threatIntelApi.matches()]);
      setSummary(s); setMatches(m);
    } catch (e) {
      setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo cargar Threat Intelligence');
    }
  }, []);

  const seq = useRef(0);
  const loadIocs = useCallback(async () => {
    const my = ++seq.current;
    try {
      const list = await threatIntelApi.iocs({ type: typeF || undefined, q: q || undefined });
      if (my === seq.current) setIocs(list);
    } catch { if (my === seq.current) setIocs([]); }
  }, [typeF, q]);

  useEffect(() => { void loadAll(); }, [loadAll]);
  useEffect(() => { void loadIocs(); }, [loadIocs]);
  // IPs ya bloqueadas en SonicWall → marcarlas al entrar (persistente entre recargas).
  useEffect(() => {
    if (!canManage) return;
    responseApi.blocked()
      .then((list) => setBlocked((prev) => { const n = { ...prev }; for (const it of list) if (!n[it.ip]) n[it.ip] = { ok: true, permanent: it.permanent }; return n; }))
      .catch(() => undefined);
  }, [canManage]);

  async function refresh() {
    setRefreshing(true);
    try { await threatIntelApi.refresh(); await loadAll(); await loadIocs(); }
    catch (e) { setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudieron refrescar los feeds'); }
    finally { setRefreshing(false); }
  }

  async function block(ip: string, rule: string) {
    setBlocked((b) => ({ ...b, [ip]: { busy: true } }));
    try {
      await responseApi.block(ip, `IOC malicioso (${rule || 'threat intel'})`.slice(0, 200));
      setBlocked((b) => ({ ...b, [ip]: { ok: true, permanent: true } })); // manual = permanente
    } catch (e) {
      setBlocked((b) => ({ ...b, [ip]: { error: (e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo bloquear' } }));
    }
  }

  async function del(id: string) {
    if (!confirm('¿Eliminar este IOC?')) return;
    await threatIntelApi.removeIoc(id).catch(() => undefined);
    await loadIocs(); await loadAll();
  }

  return (
    <div className="mx-auto max-w-6xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 hw-mono text-2xl font-bold tracking-tight">
            <Radar className="h-6 w-6 text-neon" /> Threat Intelligence
          </h1>
          <p className="text-sm text-muted-foreground">Indicadores de compromiso (IOCs) y coincidencias contra tus alertas</p>
        </div>
        {canManage && (
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => setShowAdd(true)}><Plus className="h-4 w-4" /> IOC manual</Button>
            <Button size="sm" onClick={() => void refresh()} disabled={refreshing}>
              {refreshing ? <Loader2 className="h-4 w-4 animate-spin" /> : <Rss className="h-4 w-4" />} Refrescar feeds
            </Button>
          </div>
        )}
      </div>

      {error && <Card><CardContent className="p-4 text-sm text-amber-700">{error}</CardContent></Card>}

      {/* KPIs */}
      <div className="grid gap-3 sm:grid-cols-4">
        <Card><CardContent className="p-4"><p className="text-xs text-muted-foreground">IOCs totales</p><p className="text-2xl font-bold tabular-nums">{summary?.total ?? '—'}</p></CardContent></Card>
        <Card><CardContent className="p-4"><p className="text-xs text-muted-foreground">Dominios · URLs · Hashes</p><p className="text-2xl font-bold tabular-nums">{((summary?.byType?.domain ?? 0) + (summary?.byType?.url ?? 0) + (summary?.byType?.md5 ?? 0) + (summary?.byType?.sha1 ?? 0) + (summary?.byType?.sha256 ?? 0)).toLocaleString('es-CO')}</p></CardContent></Card>
        <Card><CardContent className="p-4"><p className="text-xs text-muted-foreground">Coincidencias (24h)</p><p className="text-2xl font-bold tabular-nums text-rose-600">{matches?.length ?? '—'}</p></CardContent></Card>
        <Card><CardContent className="p-4"><p className="text-xs text-muted-foreground">Feeds</p><p className="text-2xl font-bold tabular-nums">{summary?.feeds?.length ?? 0}</p></CardContent></Card>
      </div>

      {/* Coincidencias — lo accionable */}
      <Card className="border-rose-500/30">
        <CardContent className="p-0">
          <div className="flex items-center gap-2 border-b border-border/60 px-4 py-2.5">
            <ShieldAlert className="h-4 w-4 text-rose-600" />
            <span className="text-sm font-semibold">Coincidencias: IOCs (IP, dominio, URL, hash) vistos en tus alertas (24 h)</span>
          </div>
          {!matches ? (
            <p className="flex items-center gap-2 p-4 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Cargando…</p>
          ) : matches.length === 0 ? (
            <p className="py-8 text-center text-sm text-emerald-600">✓ Ningún indicador de tus alertas coincide con un IOC conocido. Todo limpio.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border/60 text-left text-xs text-muted-foreground">
                    <th className="px-4 py-2 font-medium">Tipo</th>
                    <th className="px-2 py-2 font-medium">Indicador</th>
                    <th className="px-2 py-2 font-medium">Fuente IOC</th>
                    <th className="px-2 py-2 font-medium text-right">Alertas</th>
                    <th className="px-2 py-2 font-medium">Última vez</th>
                    <th className="px-2 py-2 font-medium">Regla / agente</th>
                    <th className="px-2 py-2 font-medium text-right">Acción</th>
                  </tr>
                </thead>
                <tbody>
                  {matches.map((m) => {
                    const st = blocked[m.value];
                    return (
                      <tr key={`${m.type}-${m.value}`} className="border-b border-border/30 last:border-0 bg-rose-500/[0.03] hover:bg-rose-500/[0.07]">
                        <td className="px-4 py-2"><span className="rounded border border-rose-500/30 bg-rose-500/10 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-rose-700">{m.type}</span></td>
                        <td className="max-w-[16rem] truncate px-2 py-2 font-mono text-xs font-semibold" title={m.value}>{m.value}</td>
                        <td className="px-2 py-2 text-xs text-muted-foreground">{m.source}</td>
                        <td className="px-2 py-2 text-right font-semibold tabular-nums">{m.alertCount.toLocaleString('es-CO')}</td>
                        <td className="whitespace-nowrap px-2 py-2 text-xs text-muted-foreground">{m.lastSeen ? new Date(m.lastSeen).toLocaleString('es-CO') : '—'}</td>
                        <td className="max-w-xs px-2 py-2"><span className="block truncate text-xs">{m.sampleRule}</span><span className="text-[10px] text-muted-foreground">{m.agent}</span></td>
                        <td className="px-2 py-2 text-right">
                          <div className="flex flex-col items-end gap-1">
                            <div className="flex items-center gap-1">
                              <Link to={m.type === 'ip' ? `/alertas?srcip=${encodeURIComponent(m.value)}` : `/alertas?q=${encodeURIComponent(m.value)}`} className="inline-flex items-center gap-1 rounded px-1.5 py-1 text-[11px] text-neon hover:underline"><ExternalLink className="h-3 w-3" /> ver</Link>
                              {canManage && m.type === 'ip' && (
                                st?.ok ? (
                                  <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/40 bg-emerald-500/10 px-2 py-1 text-[11px] font-medium text-emerald-600" title={st.permanent ? 'Bloqueada en SonicWall · permanente' : 'Bloqueada en SonicWall · temporal (24 h)'}>
                                    <ShieldCheck className="h-3.5 w-3.5" /> Bloqueada · {st.permanent ? 'permanente' : '24h'}
                                  </span>
                                ) : (
                                  <Button size="sm" variant="destructive" onClick={() => void block(m.value, m.sampleRule)} disabled={st?.busy}>
                                    {st?.busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Ban className="h-4 w-4" />} Bloquear
                                  </Button>
                                )
                              )}
                            </div>
                            {st?.error && <span className="text-[11px] text-destructive">{st.error}</span>}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Feeds */}
      {summary?.feeds && summary.feeds.length > 0 && (
        <Card>
          <CardContent className="p-4">
            <p className="mb-2 text-sm font-semibold">Feeds</p>
            <div className="space-y-1.5">
              {summary.feeds.map((f) => (
                <div key={f.name} className="flex items-center justify-between gap-3 text-xs">
                  <span className="font-medium">{f.name}</span>
                  <span className="flex items-center gap-3 text-muted-foreground">
                    <span>{f.last_count.toLocaleString('es-CO')} IOCs</span>
                    <span>{f.last_run_at ? new Date(f.last_run_at).toLocaleString('es-CO') : 'nunca'}</span>
                    <span style={{ color: f.last_status === 'ok' ? '#059669' : f.last_status === 'nunca ejecutado' ? '#9ca3af' : '#dc2626' }}>{f.last_status}</span>
                  </span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Catálogo de IOCs */}
      <Card>
        <CardContent className="p-0">
          <div className="flex flex-wrap items-center gap-2 border-b border-border/60 p-3">
            <select value={typeF} onChange={(e) => setTypeF(e.target.value)} className="h-9 rounded-md border border-input bg-background/60 px-2 text-sm">
              <option value="">Todos los tipos</option>
              {TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
            <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Buscar valor…" className="h-9 max-w-xs" />
            <span className="ml-auto text-xs text-muted-foreground">{iocs?.length ?? 0} mostrados</span>
          </div>
          {!iocs ? (
            <p className="flex items-center gap-2 p-4 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Cargando…</p>
          ) : iocs.length === 0 ? (
            <p className="py-8 text-center text-sm text-muted-foreground">Sin IOCs. Refresca los feeds o agrega uno manual.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border/60 text-left text-xs text-muted-foreground">
                    <th className="px-4 py-2 font-medium">Tipo</th>
                    <th className="px-2 py-2 font-medium">Valor</th>
                    <th className="px-2 py-2 font-medium">Fuente</th>
                    <th className="px-2 py-2 font-medium">Confianza</th>
                    <th className="px-2 py-2 font-medium text-right">Matches</th>
                    {canManage && <th className="px-2 py-2 font-medium text-right">Acción</th>}
                  </tr>
                </thead>
                <tbody>
                  {iocs.map((i) => (
                    <tr key={i.id} className={`border-b border-border/30 last:border-0 hover:bg-secondary/40 ${!i.enabled ? 'opacity-45' : ''}`}>
                      <td className="whitespace-nowrap px-4 py-2"><span className="rounded bg-secondary px-1.5 py-0.5 text-[10px] font-semibold uppercase">{i.ioc_type}</span></td>
                      <td className="max-w-md px-2 py-2 font-mono text-[11px]"><span className="block truncate">{i.value}</span></td>
                      <td className="px-2 py-2 text-xs text-muted-foreground">{i.source}</td>
                      <td className="px-2 py-2">
                        <div className="flex items-center gap-2" title={`Confianza ${i.effective_confidence}/100${i.last_seen_feed ? ` · visto hace ${i.age_days}d` : ' · manual'}${!i.enabled ? ' · envejecido (deshabilitado)' : ''}`}>
                          <div className="h-1.5 w-14 shrink-0 overflow-hidden rounded-full bg-secondary">
                            <div className="h-full rounded-full" style={{ width: `${i.effective_confidence}%`, background: i.effective_confidence >= 70 ? 'hsl(var(--destructive))' : i.effective_confidence >= 40 ? 'hsl(var(--warn-orange))' : 'hsl(var(--muted-foreground))' }} />
                          </div>
                          <span className="hw-mono text-[10px] text-muted-foreground">{i.effective_confidence}{i.last_seen_feed && i.age_days > 0 ? ` · ${i.age_days}d` : ''}</span>
                        </div>
                      </td>
                      <td className="px-2 py-2 text-right tabular-nums text-muted-foreground">{i.match_count}</td>
                      {canManage && (
                        <td className="px-2 py-2 text-right">
                          <Button size="sm" variant="ghost" onClick={() => void del(i.id)} title="Eliminar IOC"><Trash2 className="h-4 w-4 text-destructive" /></Button>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {showAdd && <AddIocModal onClose={() => setShowAdd(false)} onAdded={() => { setShowAdd(false); void loadIocs(); void loadAll(); }} />}
    </div>
  );
}

function AddIocModal({ onClose, onAdded }: { onClose: () => void; onAdded: () => void }) {
  const [type, setType] = useState<IocType>('ip');
  const [value, setValue] = useState('');
  const [description, setDescription] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function add() {
    if (!value.trim()) { setErr('Indica el valor'); return; }
    setBusy(true); setErr(null);
    try {
      await threatIntelApi.addIoc({ type, value: value.trim(), description: description.trim() || undefined });
      onAdded();
    } catch (e) {
      setErr((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo agregar');
    } finally { setBusy(false); }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div className="w-full max-w-md rounded-lg border border-border/70 bg-card shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between border-b border-border/60 px-5 py-3">
          <h3 className="font-semibold">Agregar IOC manual</h3>
          <Button variant="ghost" size="icon" onClick={onClose}><X className="h-4 w-4" /></Button>
        </div>
        <div className="space-y-3 p-5">
          <div className="space-y-1.5">
            <label className="text-xs text-muted-foreground">Tipo</label>
            <select value={type} onChange={(e) => setType(e.target.value as IocType)} className="h-9 w-full rounded-md border border-input bg-background/60 px-2 text-sm">
              {TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          </div>
          <div className="space-y-1.5">
            <label className="text-xs text-muted-foreground">Valor</label>
            <Input value={value} onChange={(e) => setValue(e.target.value)} placeholder={type === 'ip' ? '203.0.113.7' : type === 'domain' ? 'malicioso.com' : type === 'url' ? 'http://…' : 'hash…'} />
          </div>
          <div className="space-y-1.5">
            <label className="text-xs text-muted-foreground">Descripción (opcional)</label>
            <Input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="contexto del indicador" />
          </div>
          {err && <p className="text-sm text-destructive">{err}</p>}
          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={onClose} disabled={busy}>Cancelar</Button>
            <Button onClick={() => void add()} disabled={busy}>{busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />} Agregar</Button>
          </div>
        </div>
      </div>
    </div>
  );
}
