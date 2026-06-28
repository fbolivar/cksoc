/**
 * File Integrity Monitoring (FIM): cambios en archivos y claves de registro
 * (added / modified / deleted) con el usuario responsable y el activo.
 */
import { useEffect, useState } from 'react';
import { AxiosError } from 'axios';
import { FileSearch, RefreshCw, Loader2, Server, User, FilePlus2, FilePen, FileX2 } from 'lucide-react';
import { fimApi, EVENT_META, type FimData } from '@/lib/fim';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { RangeTabs, RANGE_24_7_30 } from '@/components/shared/RangeTabs';

type Range = '24h' | '7d' | '30d';
const HOURS: Record<Range, number> = { '24h': 24, '7d': 168, '30d': 720 };

function Kpi({ label, value, color, icon: Icon }: { label: string; value: number; color?: string; icon: typeof Server }) {
  return (
    <Card>
      <CardContent className="p-4">
        <div className="flex items-center justify-between">
          <span className="text-xs text-muted-foreground">{label}</span>
          <Icon className="h-4 w-4 text-muted-foreground" />
        </div>
        <p className="mt-1 text-2xl font-semibold tabular-nums" style={color ? { color } : undefined}>
          {value.toLocaleString('es-CO')}
        </p>
      </CardContent>
    </Card>
  );
}

function EventChip({ e }: { e: string }) {
  const m = EVENT_META[e] ?? { color: '#94a3b8', label: e };
  return (
    <span className="inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-semibold"
      style={{ background: `${m.color}22`, color: m.color }}>
      {m.label}
    </span>
  );
}

export default function Fim() {
  const [range, setRange] = useState<Range>('7d');
  const [data, setData] = useState<FimData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function load(r: Range) {
    setLoading(true);
    setError(null);
    try {
      setData(await fimApi.get(HOURS[r]));
    } catch (e) {
      setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo cargar FIM');
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => { load(range); }, [range]);

  const r = data?.resumen;
  const maxAg = Math.max(1, ...(data?.porAgente ?? []).map((a) => a.count));

  return (
    <div className="mx-auto max-w-7xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
            <FileSearch className="h-6 w-6 text-neon" /> File Integrity Monitoring
          </h1>
          <p className="text-sm text-muted-foreground">
            Cambios en archivos y claves de registro vigilados por Wazuh (syscheck)
          </p>
        </div>
        <div className="flex items-center gap-2">
          <RangeTabs value={range} onChange={setRange} options={RANGE_24_7_30} />
          <Button variant="outline" size="sm" onClick={() => load(range)} disabled={loading}>
            <RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} /> Actualizar
          </Button>
        </div>
      </div>

      {error && <Card><CardContent className="p-4 text-sm text-amber-200">{error}</CardContent></Card>}

      {loading && !data ? (
        <p className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" /> Cargando cambios de integridad…
        </p>
      ) : r && r.total === 0 ? (
        <Card><CardContent className="py-12 text-center text-sm text-muted-foreground">
          Sin cambios de integridad en este periodo.
        </CardContent></Card>
      ) : r && data && (
        <>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
            <Kpi label="Cambios totales" value={r.total} icon={FileSearch} />
            <Kpi label="Añadidos" value={r.added} color={EVENT_META.added.color} icon={FilePlus2} />
            <Kpi label="Modificados" value={r.modified} color={EVENT_META.modified.color} icon={FilePen} />
            <Kpi label="Eliminados" value={r.deleted} color={EVENT_META.deleted.color} icon={FileX2} />
            <Kpi label="Activos" value={r.agentes} icon={Server} />
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            {/* Por agente */}
            <Card>
              <CardHeader><CardTitle className="text-muted-foreground">Cambios por activo</CardTitle></CardHeader>
              <CardContent className="space-y-3">
                {data.porAgente.map((a) => (
                  <div key={a.agent}>
                    <div className="mb-1 flex items-center justify-between text-sm">
                      <span className="flex items-center gap-1.5 font-mono text-xs"><Server className="h-3.5 w-3.5 text-muted-foreground" />{a.agent}</span>
                      <span className="tabular-nums text-muted-foreground">{a.count}</span>
                    </div>
                    <div className="h-2 w-full overflow-hidden rounded-full bg-secondary">
                      <div className="h-full bg-primary/70" style={{ width: `${(a.count / maxAg) * 100}%` }} />
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>

            {/* Rutas mas afectadas */}
            <Card>
              <CardHeader><CardTitle className="text-muted-foreground">Rutas con más cambios</CardTitle></CardHeader>
              <CardContent className="space-y-2">
                {data.topPaths.map((p) => (
                  <div key={p.path} className="flex items-center gap-2 text-xs">
                    <span className="tabular-nums rounded bg-secondary px-1.5 py-0.5 text-[10px] text-muted-foreground">{p.count}</span>
                    <span className="truncate font-mono text-muted-foreground" title={p.path}>{p.path}</span>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>

          {/* Cambios recientes */}
          <Card>
            <CardHeader><CardTitle className="text-muted-foreground">Cambios recientes ({data.recientes.length})</CardTitle></CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border/60 text-left text-xs text-muted-foreground">
                      <th className="pb-2 pr-3 font-medium">Evento</th>
                      <th className="pb-2 pr-3 font-medium">Ruta</th>
                      <th className="pb-2 pr-3 font-medium">Usuario</th>
                      <th className="pb-2 pr-3 font-medium">Activo</th>
                      <th className="pb-2 font-medium">Hora</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.recientes.map((c, i) => (
                      <tr key={`${c.timestamp}-${c.path}-${i}`} className="border-b border-border/30 last:border-0">
                        <td className="py-2 pr-3"><EventChip e={c.event} /></td>
                        <td className="py-2 pr-3 max-w-md">
                          <span className="block truncate font-mono text-xs" title={c.path}>{c.path}</span>
                          {c.mode && <span className="text-[10px] text-muted-foreground/50">{c.mode}</span>}
                        </td>
                        <td className="py-2 pr-3 text-xs text-muted-foreground">
                          {c.user ? <span className="flex items-center gap-1"><User className="h-3 w-3" />{c.user}</span> : '—'}
                        </td>
                        <td className="py-2 pr-3 font-mono text-[11px] text-muted-foreground">{c.agent}</td>
                        <td className="py-2 text-xs text-muted-foreground">{c.timestamp ? new Date(c.timestamp).toLocaleString('es-CO') : '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
