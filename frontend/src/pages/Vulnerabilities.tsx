/**
 * Deteccion de Vulnerabilidades (Wazuh Vulnerability Detector).
 * Resumen por severidad, top CVE, vulnerabilidades por agente y paquete, y
 * listado detallado con enlace a la ficha CTI de Wazuh.
 */
import { useEffect, useState } from 'react';
import { AxiosError } from 'axios';
import { ShieldAlert, RefreshCw, Loader2, ExternalLink, Server, Package, Bug } from 'lucide-react';
import { vulnApi, SEV_COLOR, SEV_LABEL, type VulnData, type Severity } from '@/lib/vulnerabilities';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

function SevChip({ s }: { s: Severity }) {
  return (
    <span
      className="inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-semibold"
      style={{ background: `${SEV_COLOR[s]}22`, color: SEV_COLOR[s] }}
    >
      {SEV_LABEL[s]}
    </span>
  );
}

function Kpi({ label, value, color, icon: Icon }: { label: string; value: number; color?: string; icon: typeof Server }) {
  return (
    <Card>
      <CardContent className="p-4">
        <div className="flex items-center justify-between">
          <span className="text-xs text-muted-foreground">{label}</span>
          <Icon className="h-4 w-4 text-muted-foreground" />
        </div>
        <p className="mt-1 text-3xl font-semibold tabular-nums" style={color ? { color } : undefined}>
          {value.toLocaleString('es-CO')}
        </p>
      </CardContent>
    </Card>
  );
}

export default function Vulnerabilities() {
  const [data, setData] = useState<VulnData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      setData(await vulnApi.get());
    } catch (e) {
      setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudieron cargar las vulnerabilidades');
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => { load(); }, []);

  const r = data?.resumen;
  const maxAgente = Math.max(1, ...(data?.porAgente ?? []).map((a) => a.total));

  return (
    <div className="mx-auto max-w-7xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
            <ShieldAlert className="h-6 w-6 text-neon" /> Vulnerabilidades
          </h1>
          <p className="text-sm text-muted-foreground">
            CVEs detectados por el Vulnerability Detector de Wazuh en los activos monitoreados
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={load} disabled={loading}>
          <RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} /> Actualizar
        </Button>
      </div>

      {error && (
        <Card><CardContent className="p-4 text-sm text-amber-200">{error}</CardContent></Card>
      )}

      {loading && !data ? (
        <p className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" /> Cargando vulnerabilidades…
        </p>
      ) : r && r.total === 0 ? (
        <Card><CardContent className="py-12 text-center text-sm text-muted-foreground">
          No hay vulnerabilidades reportadas. El módulo Vulnerability Detector aún no ha publicado resultados.
        </CardContent></Card>
      ) : r && (
        <>
          {/* KPIs */}
          <div className="grid gap-4 sm:grid-cols-3 lg:grid-cols-6">
            <Kpi label="Total" value={r.total} icon={Bug} />
            <Kpi label="Críticas" value={r.critical} color={SEV_COLOR.Critical} icon={ShieldAlert} />
            <Kpi label="Altas" value={r.high} color={SEV_COLOR.High} icon={ShieldAlert} />
            <Kpi label="Medias" value={r.medium} color={SEV_COLOR.Medium} icon={ShieldAlert} />
            <Kpi label="CVEs únicas" value={r.cves} icon={Bug} />
            <Kpi label="Activos afectados" value={r.agentes} icon={Server} />
          </div>

          {/* Distribucion por severidad */}
          <Card>
            <CardContent className="p-4">
              <div className="mb-2 text-xs text-muted-foreground">Distribución por severidad</div>
              <div className="flex h-3 w-full overflow-hidden rounded-full bg-secondary">
                {(['Critical', 'High', 'Medium', 'Low'] as Severity[]).map((s) => {
                  const v = s === 'Critical' ? r.critical : s === 'High' ? r.high : s === 'Medium' ? r.medium : r.low;
                  const pct = r.total ? (v / r.total) * 100 : 0;
                  return pct > 0 ? <div key={s} style={{ width: `${pct}%`, background: SEV_COLOR[s] }} title={`${SEV_LABEL[s]}: ${v}`} /> : null;
                })}
              </div>
              <div className="mt-2 flex flex-wrap gap-4 text-[11px] text-muted-foreground">
                {(['Critical', 'High', 'Medium', 'Low'] as Severity[]).map((s) => (
                  <span key={s} className="flex items-center gap-1.5">
                    <span className="h-2 w-2 rounded-full" style={{ background: SEV_COLOR[s] }} />
                    {SEV_LABEL[s]}: <b>{s === 'Critical' ? r.critical : s === 'High' ? r.high : s === 'Medium' ? r.medium : r.low}</b>
                  </span>
                ))}
              </div>
            </CardContent>
          </Card>

          <div className="grid gap-4 lg:grid-cols-2">
            {/* Top CVE */}
            <Card>
              <CardHeader><CardTitle className="text-muted-foreground">Top CVE (por activos afectados)</CardTitle></CardHeader>
              <CardContent className="space-y-2.5">
                {data.topCve.map((c) => (
                  <div key={c.cve} className="flex items-start gap-2.5">
                    <SevChip s={c.severity} />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <a href={`https://cti.wazuh.com/vulnerabilities/cves/${c.cve}`} target="_blank" rel="noreferrer"
                          className="font-mono text-sm text-neon hover:underline">{c.cve}</a>
                        {c.score != null && <span className="text-[10px] text-muted-foreground">CVSS {c.score}</span>}
                      </div>
                      <p className="truncate text-[11px] text-muted-foreground">{c.description}</p>
                    </div>
                    <span className="tabular-nums text-sm font-medium">{c.count}</span>
                  </div>
                ))}
              </CardContent>
            </Card>

            {/* Por agente */}
            <Card>
              <CardHeader><CardTitle className="text-muted-foreground">Vulnerabilidades por activo</CardTitle></CardHeader>
              <CardContent className="space-y-3">
                {data.porAgente.map((a) => (
                  <div key={a.agent}>
                    <div className="mb-1 flex items-center justify-between text-sm">
                      <span className="flex items-center gap-1.5 font-mono text-xs"><Server className="h-3.5 w-3.5 text-muted-foreground" />{a.agent}</span>
                      <span className="tabular-nums text-muted-foreground">
                        {a.critical > 0 && <span style={{ color: SEV_COLOR.Critical }}>{a.critical} crít · </span>}
                        {a.high > 0 && <span style={{ color: SEV_COLOR.High }}>{a.high} alta · </span>}
                        <b>{a.total}</b>
                      </span>
                    </div>
                    <div className="h-2 w-full overflow-hidden rounded-full bg-secondary">
                      <div className="h-full bg-primary/70" style={{ width: `${(a.total / maxAgente) * 100}%` }} />
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>

          {/* Listado detallado */}
          <Card>
            <CardHeader><CardTitle className="text-muted-foreground">Detalle de vulnerabilidades ({data.items.length})</CardTitle></CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border/60 text-left text-xs text-muted-foreground">
                      <th className="pb-2 pr-3 font-medium">CVE</th>
                      <th className="pb-2 pr-3 font-medium">Sev.</th>
                      <th className="pb-2 pr-3 font-medium">CVSS</th>
                      <th className="pb-2 pr-3 font-medium">Paquete</th>
                      <th className="pb-2 pr-3 font-medium">Activo</th>
                      <th className="pb-2 font-medium">Descripción</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.items.map((v, i) => (
                      <tr key={i} className="border-b border-border/30 last:border-0 align-top">
                        <td className="py-2 pr-3">
                          <a href={v.reference?.split(',')[0] || `https://cti.wazuh.com/vulnerabilities/cves/${v.cve}`}
                            target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 font-mono text-xs text-neon hover:underline">
                            {v.cve}<ExternalLink className="h-3 w-3" />
                          </a>
                        </td>
                        <td className="py-2 pr-3"><SevChip s={v.severity} /></td>
                        <td className="py-2 pr-3 tabular-nums text-muted-foreground">{v.score ?? '—'}</td>
                        <td className="py-2 pr-3">
                          <span className="flex items-center gap-1 text-xs"><Package className="h-3 w-3 text-muted-foreground" />{v.packageName}</span>
                          <span className="text-[10px] text-muted-foreground/60">{v.packageVersion}</span>
                        </td>
                        <td className="py-2 pr-3 font-mono text-[11px] text-muted-foreground">{v.agent}</td>
                        <td className="py-2 max-w-md text-xs text-muted-foreground">{v.description}</td>
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
