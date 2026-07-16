/**
 * Explorador de Alertas: busqueda y filtrado de eventos individuales de Wazuh
 * (tiempo, severidad, regla, agente, IP, texto) con panel de detalle del evento.
 */
import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { AxiosError } from 'axios';
import { ListFilter, RefreshCw, Loader2, X, ChevronLeft, ChevronRight, Search, Briefcase } from 'lucide-react';
import { alertsApi, BAND_COLOR, BAND_LABEL, type AlertHit, type AlertFilters } from '@/lib/alerts';
import { incidentsApi, type Severity } from '@/lib/incidents';
import { useAuth } from '@/lib/auth';
import { downloadCsv, fileStamp, type CsvCol } from '@/lib/csv';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { RangeTabs, RANGE_24_7_30 } from '@/components/shared/RangeTabs';
import { ExportButton } from '@/components/shared/ExportButton';

const SIZE = 25;
const EXPORT_MAX = 1000; // tope de filas a exportar (10 paginas de 100)

const ALERT_COLS: CsvCol<AlertHit>[] = [
  { label: 'Fecha', get: (h) => h.timestamp },
  { label: 'Nivel', get: (h) => h.level },
  { label: 'Banda', get: (h) => BAND_LABEL[h.band] },
  { label: 'Regla', get: (h) => h.ruleId },
  { label: 'Descripción', get: (h) => h.description },
  { label: 'Agente', get: (h) => h.agent },
  { label: 'IP origen', get: (h) => h.srcip ?? '' },
  { label: 'MITRE', get: (h) => h.mitre.join(' ') },
  { label: 'Grupos', get: (h) => h.groups.join(' ') },
];

function SevDot({ band, level }: { band: AlertHit['band']; level: number }) {
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-xs" style={{ color: BAND_COLOR[band] }}>
      <span className="h-2 w-2 rounded-full" style={{ background: BAND_COLOR[band] }} />
      {level} · {BAND_LABEL[band]}
    </span>
  );
}

export default function Alerts() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const canManage = user?.role === 'admin' || user?.role === 'analista';
  const [escalating, setEscalating] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [range, setRange] = useState('24h');
  const [band, setBand] = useState('');
  const [agent, setAgent] = useState('');
  const [srcip, setSrcip] = useState('');
  const [ruleId, setRuleId] = useState('');
  const [q, setQ] = useState('');
  const [page, setPage] = useState(0);

  const [data, setData] = useState<{ total: number; capped: boolean; items: AlertHit[] } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [detail, setDetail] = useState<{ hit: AlertHit; source: Record<string, unknown> | null } | null>(null);

  const load = useCallback(async (f: AlertFilters) => {
    setLoading(true); setError(null);
    try {
      setData(await alertsApi.search(f));
    } catch (e) {
      setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo buscar alertas');
    } finally {
      setLoading(false);
    }
  }, []);

  // Recarga al cambiar rango o pagina; los filtros de texto se aplican con "Buscar".
  useEffect(() => {
    load({ range, band: band || undefined, agent: agent || undefined, srcip: srcip || undefined, ruleId: ruleId || undefined, q: q || undefined, page, size: SIZE });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [range, page, band]);

  function applyFilters() {
    if (page !== 0) setPage(0);
    else load({ range, band: band || undefined, agent: agent || undefined, srcip: srcip || undefined, ruleId: ruleId || undefined, q: q || undefined, page: 0, size: SIZE });
  }

  async function openDetail(hit: AlertHit) {
    setDetail({ hit, source: null });
    try {
      const source = await alertsApi.detail(hit.index, hit.id);
      setDetail({ hit, source });
    } catch {
      setDetail({ hit, source: { error: 'No se pudo cargar el detalle' } });
    }
  }

  async function escalate(hit: AlertHit) {
    setEscalating(true);
    try {
      await incidentsApi.create({
        title: (hit.description || `Alerta regla ${hit.ruleId}`).slice(0, 180),
        severity: hit.band as Severity,
        source: { alertId: hit.id, index: hit.index, ip: hit.srcip ?? undefined, agent: hit.agent, ruleId: hit.ruleId, description: hit.description, alertTime: hit.timestamp },
      });
      navigate('/incidentes');
    } catch {
      /* el error se ignora; el boton vuelve a estar disponible */
    } finally {
      setEscalating(false);
    }
  }

  // Exporta hasta EXPORT_MAX filas que cumplan los filtros actuales (varias paginas).
  async function exportCsv() {
    setExporting(true);
    try {
      const base = { range, band: band || undefined, agent: agent || undefined, srcip: srcip || undefined, ruleId: ruleId || undefined, q: q || undefined };
      const PSIZE = 100;
      const all: AlertHit[] = [];
      for (let p = 0; p * PSIZE < EXPORT_MAX; p++) {
        const res = await alertsApi.search({ ...base, page: p, size: PSIZE });
        all.push(...res.items);
        if (all.length >= res.total || res.items.length < PSIZE) break;
      }
      downloadCsv(`alertas-${range}-${fileStamp()}.csv`, all, ALERT_COLS);
    } catch {
      /* noop: el boton se reactiva */
    } finally {
      setExporting(false);
    }
  }

  const total = data?.total ?? 0;
  const maxPage = Math.min(Math.ceil(total / SIZE) - 1, Math.floor(10000 / SIZE) - 1);

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
            <ListFilter className="h-6 w-6 text-neon" /> Explorador de Alertas
          </h1>
          <p className="text-sm text-muted-foreground">Busca e inspecciona eventos individuales de Wazuh</p>
        </div>
        <div className="flex items-center gap-2">
          <RangeTabs value={range} onChange={(v) => { setPage(0); setRange(v); }} options={RANGE_24_7_30} />
          <ExportButton onExport={exportCsv} busy={exporting} disabled={loading || total === 0} />
          <Button variant="outline" size="sm" onClick={() => load({ range, band: band || undefined, agent: agent || undefined, srcip: srcip || undefined, ruleId: ruleId || undefined, q: q || undefined, page, size: SIZE })} disabled={loading}>
            <RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} />
          </Button>
        </div>
      </div>

      {/* Filtros */}
      <Card>
        <CardContent className="flex flex-wrap items-end gap-2 p-3">
          <select value={band} onChange={(e) => { setPage(0); setBand(e.target.value); }}
            className="h-9 rounded-md border border-input bg-background/60 px-2 text-sm">
            <option value="">Toda severidad</option>
            <option value="critica">Crítica</option>
            <option value="alta">Alta</option>
            <option value="media">Media</option>
            <option value="baja">Baja</option>
          </select>
          <Input value={agent} onChange={(e) => setAgent(e.target.value)} placeholder="Agente" className="h-9 w-36" onKeyDown={(e) => e.key === 'Enter' && applyFilters()} />
          <Input value={srcip} onChange={(e) => setSrcip(e.target.value)} placeholder="IP origen" className="h-9 w-36" onKeyDown={(e) => e.key === 'Enter' && applyFilters()} />
          <Input value={ruleId} onChange={(e) => setRuleId(e.target.value)} placeholder="ID regla" className="h-9 w-28" onKeyDown={(e) => e.key === 'Enter' && applyFilters()} />
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Buscar en descripción…" className="h-9 flex-1" style={{ minWidth: 180 }} onKeyDown={(e) => e.key === 'Enter' && applyFilters()} />
          <Button size="sm" onClick={applyFilters} disabled={loading}><Search className="h-4 w-4" /> Buscar</Button>
        </CardContent>
      </Card>

      {error && <Card><CardContent className="p-4 text-sm text-amber-200">{error}</CardContent></Card>}

      {/* Resultados */}
      <Card>
        <CardContent className="p-0">
          <div className="flex items-center justify-between border-b border-border/60 px-4 py-2 text-xs text-muted-foreground">
            <span>{total.toLocaleString('es-CO')}{data?.capped ? '+' : ''} resultados</span>
            <span className="flex items-center gap-2">
              <Button variant="ghost" size="icon" className="h-7 w-7" disabled={page <= 0 || loading} onClick={() => setPage((p) => Math.max(0, p - 1))}><ChevronLeft className="h-4 w-4" /></Button>
              página {page + 1}{maxPage >= 0 ? ` / ${maxPage + 1}` : ''}
              <Button variant="ghost" size="icon" className="h-7 w-7" disabled={page >= maxPage || loading} onClick={() => setPage((p) => p + 1)}><ChevronRight className="h-4 w-4" /></Button>
            </span>
          </div>
          {loading && !data ? (
            <p className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Buscando…</p>
          ) : data && data.items.length === 0 ? (
            <p className="py-12 text-center text-sm text-muted-foreground">Sin alertas que coincidan con los filtros.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border/60 text-left text-xs text-muted-foreground">
                    <th className="px-4 py-2 font-medium">Hora</th>
                    <th className="px-2 py-2 font-medium">Severidad</th>
                    <th className="px-2 py-2 font-medium">Regla</th>
                    <th className="px-2 py-2 font-medium">Agente</th>
                    <th className="px-2 py-2 font-medium">IP origen</th>
                    <th className="px-2 py-2 font-medium">Descripción</th>
                  </tr>
                </thead>
                <tbody>
                  {data?.items.map((it) => (
                    <tr key={it.id} onClick={() => openDetail(it)} className="cursor-pointer border-b border-border/30 last:border-0 hover:bg-secondary/40">
                      <td className="whitespace-nowrap px-4 py-2 text-xs text-muted-foreground">{new Date(it.timestamp).toLocaleString('es-CO')}</td>
                      <td className="px-2 py-2"><SevDot band={it.band} level={it.level} /></td>
                      <td className="px-2 py-2 font-mono text-xs text-muted-foreground">{it.ruleId}</td>
                      <td className="px-2 py-2 font-mono text-[11px]">{it.agent}</td>
                      <td className="px-2 py-2 font-mono text-[11px] text-muted-foreground">{it.srcip ?? '—'}</td>
                      <td className="max-w-md px-2 py-2">
                        <span className="block truncate text-xs">{it.description}</span>
                        {it.mitre.length > 0 && <span className="text-[10px] text-neon">{it.mitre.join(', ')}</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Panel de detalle */}
      {detail && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/50" onClick={() => setDetail(null)}>
          <div className="h-full w-full max-w-2xl overflow-y-auto border-l border-border/70 bg-card shadow-2xl" onClick={(e) => e.stopPropagation()}>
            <div className="sticky top-0 flex items-center justify-between border-b border-border/60 bg-card px-5 py-3">
              <div className="flex items-center gap-3">
                <SevDot band={detail.hit.band} level={detail.hit.level} />
                <span className="font-mono text-xs text-muted-foreground">regla {detail.hit.ruleId}</span>
              </div>
              <Button variant="ghost" size="icon" onClick={() => setDetail(null)}><X className="h-4 w-4" /></Button>
            </div>
            <div className="space-y-3 p-5">
              <div>
                <p className="text-sm font-medium">{detail.hit.description}</p>
                <p className="mt-1 text-xs text-muted-foreground">
                  {new Date(detail.hit.timestamp).toLocaleString('es-CO')} · {detail.hit.agent}
                  {detail.hit.srcip ? ` · ${detail.hit.srcip}` : ''}
                </p>
                {detail.hit.mitre.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {detail.hit.mitre.map((m) => (
                      <a key={m} href={`https://attack.mitre.org/techniques/${m.replace('.', '/')}/`} target="_blank" rel="noreferrer"
                        className="rounded bg-secondary px-1.5 py-0.5 text-[10px] text-neon hover:underline">{m}</a>
                    ))}
                  </div>
                )}
                {detail.hit.groups.length > 0 && (
                  <p className="mt-1 text-[10px] text-muted-foreground/70">grupos: {detail.hit.groups.join(', ')}</p>
                )}
                {canManage && (
                  <Button size="sm" className="mt-3" onClick={() => escalate(detail.hit)} disabled={escalating}>
                    {escalating ? <Loader2 className="h-4 w-4 animate-spin" /> : <Briefcase className="h-4 w-4" />} Escalar a incidente
                  </Button>
                )}
              </div>
              <div>
                <p className="mb-1 text-xs font-medium text-muted-foreground">Evento completo</p>
                {detail.source === null ? (
                  <p className="flex items-center gap-2 py-6 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Cargando detalle…</p>
                ) : (
                  <pre className="max-h-[60vh] overflow-auto rounded-md border border-border/50 bg-secondary/30 p-3 text-[11px] leading-relaxed">
                    {JSON.stringify(detail.source, null, 2)}
                  </pre>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
