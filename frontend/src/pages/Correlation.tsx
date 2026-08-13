/**
 * Correlación multi-fuente: casos agrupados por IP de origen. Reduce la fatiga de
 * alertas mostrando UN caso por IP (con todas sus alertas de FortiGate + Wazuh),
 * priorizado por riesgo, con acción de crear un incidente unificado o bloquear.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { AxiosError } from 'axios';
import { GitMerge, RefreshCw, Loader2, Ban, CheckCircle2, ExternalLink, Layers, ShieldAlert, Globe } from 'lucide-react';
import { correlationApi, type Correlation } from '@/lib/correlation';
import { incidentsApi, type Severity } from '@/lib/incidents';
import { responseApi } from '@/lib/response';
import { useAuth } from '@/lib/auth';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { RangeTabs, RANGE_24_7_30 } from '@/components/shared/RangeTabs';

const BAND_COLOR: Record<Correlation['band'], string> = {
  critica: '#dc2626', alta: '#ea580c', media: '#ca8a04', baja: '#6b7280',
};

export default function CorrelationPage() {
  const { user } = useAuth();
  const canManage = user?.role === 'admin' || user?.role === 'analista';
  const navigate = useNavigate();

  const [range, setRange] = useState('24h');
  const [items, setItems] = useState<Correlation[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [act, setAct] = useState<Record<string, { blockBusy?: boolean; blocked?: boolean; incBusy?: boolean; err?: string }>>({});

  const seq = useRef(0);
  const load = useCallback(async (r: string) => {
    const my = ++seq.current;
    setLoading(true); setError(null);
    try {
      const list = await correlationApi.list(r);
      if (my === seq.current) setItems(list);
    } catch (e) {
      if (my === seq.current) { setItems(null); setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo cargar la correlación'); }
    } finally {
      if (my === seq.current) setLoading(false);
    }
  }, []);

  useEffect(() => { void load(range); }, [range, load]);

  async function block(ip: string) {
    setAct((a) => ({ ...a, [ip]: { ...a[ip], blockBusy: true, err: undefined } }));
    try {
      await responseApi.block(ip, 'Correlación multi-fuente');
      setAct((a) => ({ ...a, [ip]: { ...a[ip], blockBusy: false, blocked: true } }));
    } catch (e) {
      setAct((a) => ({ ...a, [ip]: { ...a[ip], blockBusy: false, err: (e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo bloquear' } }));
    }
  }

  async function createIncident(c: Correlation) {
    setAct((a) => ({ ...a, [c.srcip]: { ...a[c.srcip], incBusy: true, err: undefined } }));
    try {
      const desc = `Caso correlacionado por IP ${c.srcip}: ${c.count} alertas, ${c.distinctRules} reglas distintas, ${c.agents.length} host(s)`
        + `${c.crossSource ? ', multi-fuente (FortiGate + Wazuh)' : ''}${c.iocSource ? `, IOC conocido (${c.iocSource})` : ''}.`
        + ` Regla representativa: ${c.sampleRule}.`;
      await incidentsApi.create({
        title: `Actividad correlacionada de ${c.srcip} (${c.count} alertas)`.slice(0, 180),
        description: desc,
        severity: c.band as Severity,
        source: { ip: c.srcip, agent: c.agents[0], description: c.sampleRule, alertTime: c.lastSeen },
      });
      navigate('/incidentes');
    } catch (e) {
      setAct((a) => ({ ...a, [c.srcip]: { ...a[c.srcip], incBusy: false, err: (e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo crear el incidente' } }));
    }
  }

  const total = items?.length ?? 0;
  const cross = items?.filter((c) => c.crossSource).length ?? 0;
  const withIoc = items?.filter((c) => c.iocSource).length ?? 0;
  const external = items?.filter((c) => c.external).length ?? 0;

  return (
    <div className="mx-auto max-w-6xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
            <GitMerge className="h-6 w-6 text-neon" /> Correlación
          </h1>
          <p className="text-sm text-muted-foreground">Casos agrupados por IP de origen — un caso, no N alertas sueltas</p>
        </div>
        <div className="flex items-center gap-2">
          <RangeTabs value={range} onChange={setRange} options={RANGE_24_7_30} />
          <Button variant="outline" size="sm" onClick={() => void load(range)} disabled={loading}>
            <RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} />
          </Button>
        </div>
      </div>

      <div className="grid gap-3 sm:grid-cols-4">
        <Card><CardContent className="p-4"><p className="text-xs text-muted-foreground">Casos</p><p className="text-2xl font-bold tabular-nums">{total}</p></CardContent></Card>
        <Card><CardContent className="p-4"><p className="flex items-center gap-1.5 text-xs text-muted-foreground"><Layers className="h-3.5 w-3.5" /> Multi-fuente</p><p className="text-2xl font-bold tabular-nums text-amber-600">{cross}</p></CardContent></Card>
        <Card><CardContent className="p-4"><p className="flex items-center gap-1.5 text-xs text-muted-foreground"><ShieldAlert className="h-3.5 w-3.5" /> Con IOC</p><p className="text-2xl font-bold tabular-nums text-rose-600">{withIoc}</p></CardContent></Card>
        <Card><CardContent className="p-4"><p className="flex items-center gap-1.5 text-xs text-muted-foreground"><Globe className="h-3.5 w-3.5" /> Externas</p><p className="text-2xl font-bold tabular-nums">{external}</p></CardContent></Card>
      </div>

      {error && <Card><CardContent className="p-4 text-sm text-amber-700">{error}</CardContent></Card>}

      {loading && !items ? (
        <Card><CardContent className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Correlacionando…</CardContent></Card>
      ) : !items || items.length === 0 ? (
        <Card><CardContent className="py-12 text-center text-sm text-emerald-600">✓ Sin casos correlacionados relevantes en el rango.</CardContent></Card>
      ) : (
        <div className="space-y-3">
          {items.map((c) => {
            const a = act[c.srcip] ?? {};
            return (
              <Card key={c.srcip} style={{ borderColor: `${BAND_COLOR[c.band]}55` }}>
                <CardContent className="p-4">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-sm font-bold">{c.srcip}</span>
                        <span className="rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase" style={{ background: `${BAND_COLOR[c.band]}22`, color: BAND_COLOR[c.band] }}>{c.band}</span>
                        <span className="rounded bg-secondary px-1.5 py-0.5 text-[10px] text-muted-foreground">{c.external ? 'externa' : 'interna'}</span>
                        {c.crossSource && <span className="inline-flex items-center gap-1 rounded bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-semibold text-amber-600"><Layers className="h-3 w-3" /> multi-fuente</span>}
                        {c.iocSource && <span className="inline-flex items-center gap-1 rounded bg-rose-500/15 px-1.5 py-0.5 text-[10px] font-semibold text-rose-600"><ShieldAlert className="h-3 w-3" /> IOC: {c.iocSource}</span>}
                        <span className="ml-auto text-[10px] text-muted-foreground">riesgo {c.score}</span>
                      </div>
                      <p className="mt-1.5 text-sm">{c.sampleRule || 'Actividad correlacionada'}</p>
                      <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
                        <span><strong className="text-foreground">{c.count}</strong> alertas</span>
                        <span><strong className="text-foreground">{c.distinctRules}</strong> reglas</span>
                        <span>FortiGate: {c.fortiCount} · Wazuh: {c.wazuhCount}</span>
                        <span>hosts: {c.agents.join(', ') || '—'}</span>
                        {c.mitre.length > 0 && <span className="text-neon">{c.mitre.join(', ')}</span>}
                        <span>último: {c.lastSeen ? new Date(c.lastSeen).toLocaleString('es-CO') : '—'}</span>
                      </div>
                      {a.err && <p className="mt-1 text-[11px] text-destructive">{a.err}</p>}
                    </div>
                    <div className="flex shrink-0 flex-col items-end gap-1.5">
                      <div className="flex items-center gap-2">
                        <Link to={`/alertas?srcip=${encodeURIComponent(c.srcip)}`} className="inline-flex items-center gap-1 text-[11px] text-neon hover:underline"><ExternalLink className="h-3 w-3" /> ver alertas</Link>
                      </div>
                      {canManage && (
                        <div className="flex items-center gap-2">
                          <Button size="sm" variant="outline" onClick={() => void createIncident(c)} disabled={a.incBusy}>
                            {a.incBusy ? <Loader2 className="h-4 w-4 animate-spin" /> : <GitMerge className="h-4 w-4" />} Crear incidente
                          </Button>
                          {c.external && (a.blocked ? (
                            <span className="inline-flex items-center gap-1 text-[11px] text-emerald-600"><CheckCircle2 className="h-3.5 w-3.5" /> bloqueada</span>
                          ) : (
                            <Button size="sm" variant="destructive" onClick={() => void block(c.srcip)} disabled={a.blockBusy}>
                              {a.blockBusy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Ban className="h-4 w-4" />} Bloquear
                            </Button>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
