/**
 * Deteccion de Vulnerabilidades (Wazuh Vulnerability Detector).
 * Resumen por severidad, top CVE, vulnerabilidades por agente y paquete, y
 * listado detallado con enlace a la ficha CTI de Wazuh.
 */
import { useEffect, useState } from 'react';
import { AxiosError } from 'axios';
import { ShieldAlert, RefreshCw, Loader2, ExternalLink, Server, Package, Bug, Flame, Target } from 'lucide-react';
import { vulnApi, SEV_COLOR, SEV_LABEL, priorityBand, type VulnData, type VulnItem, type Severity, type IntelStatus } from '@/lib/vulnerabilities';
import { downloadCsv, fileStamp, type CsvCol } from '@/lib/csv';
import { useAuth } from '@/lib/auth';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { KpiCard } from '@/components/shared/KpiCard';
import { ExportButton } from '@/components/shared/ExportButton';

/** Insignia de explotación activa (CISA KEV). */
function KevBadge() {
  return <span className="inline-flex items-center gap-1 rounded border border-rose-500/30 bg-rose-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-rose-700" title="En el catálogo CISA KEV: explotada activamente en el mundo"><Flame className="h-3 w-3" /> KEV</span>;
}

/** EPSS como porcentaje (probabilidad de explotación en 30 días). */
function EpssTag({ epss }: { epss: number | null }) {
  if (epss == null) return null;
  const pct = Math.round(epss * 100);
  const cls = pct >= 50 ? 'text-rose-700' : pct >= 10 ? 'text-orange-700' : 'text-muted-foreground';
  return <span className={`text-[10px] font-medium ${cls}`} title="EPSS: probabilidad estimada de explotación en 30 días">EPSS {pct}%</span>;
}

const VULN_COLS: CsvCol<VulnItem>[] = [
  { label: 'CVE', get: (v) => v.cve },
  { label: 'Severidad', get: (v) => SEV_LABEL[v.severity] },
  { label: 'Score', get: (v) => v.score ?? '' },
  { label: 'Prioridad', get: (v) => v.priority },
  { label: 'KEV', get: (v) => (v.inKev ? 'Sí' : 'No') },
  { label: 'EPSS', get: (v) => (v.epss != null ? `${Math.round(v.epss * 100)}%` : '') },
  { label: 'Paquete', get: (v) => v.packageName },
  { label: 'Versión', get: (v) => v.packageVersion },
  { label: 'Agente', get: (v) => v.agent },
  { label: 'SO', get: (v) => v.os },
  { label: 'Detectado', get: (v) => v.detectedAt ?? '' },
  { label: 'Publicado', get: (v) => v.publishedAt ?? '' },
  { label: 'Descripción', get: (v) => v.description },
  { label: 'Referencia', get: (v) => v.reference ?? '' },
];

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

export default function Vulnerabilities() {
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';
  const [data, setData] = useState<VulnData | null>(null);
  const [intel, setIntel] = useState<IntelStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshingIntel, setRefreshingIntel] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      setData(await vulnApi.get());
      vulnApi.intel().then(setIntel).catch(() => undefined);
    } catch (e) {
      setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudieron cargar las vulnerabilidades');
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => { load(); }, []);

  async function refreshIntel() {
    setRefreshingIntel(true);
    try { setIntel(await vulnApi.refreshIntel()); await load(); }
    catch (e) { setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo refrescar la inteligencia de CVEs'); }
    finally { setRefreshingIntel(false); }
  }

  const r = data?.resumen;
  const maxAgente = Math.max(1, ...(data?.porAgente ?? []).map((a) => a.total));

  return (
    <div className="mx-auto max-w-7xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="hw-mono flex items-center gap-2 text-2xl font-bold tracking-tight">
            <ShieldAlert className="h-6 w-6 text-primary" /> VULNERABILIDADES
          </h1>
          <p className="text-sm text-muted-foreground">
            CVEs detectados por Wazuh, <b>priorizados por riesgo real</b> con CISA KEV (explotación activa) y EPSS
          </p>
          {intel && (
            <p className="mt-1 text-[11px] text-muted-foreground/70">
              Intel: {intel.kevCount.toLocaleString('es-CO')} CVEs en KEV · {intel.epssCount.toLocaleString('es-CO')} con EPSS
              {intel.feeds.find((f) => f.name === 'cisa_kev')?.last_run_at ? ` · KEV act. ${new Date(intel.feeds.find((f) => f.name === 'cisa_kev')!.last_run_at!).toLocaleDateString('es-CO')}` : ''}
            </p>
          )}
        </div>
        <div className="flex items-center gap-2">
          {isAdmin && (
            <Button variant="outline" size="sm" onClick={refreshIntel} disabled={refreshingIntel} title="Refrescar CISA KEV + EPSS">
              {refreshingIntel ? <Loader2 className="h-4 w-4 animate-spin" /> : <Target className="h-4 w-4" />} Intel
            </Button>
          )}
          <ExportButton onExport={() => downloadCsv(`vulnerabilidades-${fileStamp()}.csv`, data?.items ?? [], VULN_COLS)} disabled={!data || data.items.length === 0} label="CSV" />
          <Button variant="outline" size="sm" onClick={load} disabled={loading}>
            <RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} /> Actualizar
          </Button>
        </div>
      </div>

      {error && (
        <Card><CardContent className="p-4 text-sm text-amber-700">{error}</CardContent></Card>
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
          <div className="grid gap-4 sm:grid-cols-3 lg:grid-cols-7">
            <KpiCard label="Total" value={r.total} icon={Bug} />
            <KpiCard label="Críticas" value={r.critical} color={SEV_COLOR.Critical} icon={ShieldAlert} />
            <KpiCard label="Altas" value={r.high} color={SEV_COLOR.High} icon={ShieldAlert} />
            <KpiCard label="Explotadas (KEV)" value={r.kev} color="#dc2626" icon={Flame} />
            <KpiCard label="Explotables (EPSS↑)" value={r.exploitable} color="#ea580c" icon={Target} />
            <KpiCard label="CVEs únicas" value={r.cves} icon={Bug} />
            <KpiCard label="Activos afectados" value={r.agentes} icon={Server} />
          </div>

          {/* Priorización por riesgo real (KEV + EPSS + CVSS) */}
          {data.priorizadas.length > 0 && (
            <Card className={data.priorizadas.some((p) => p.inKev) ? 'border-rose-500/30' : ''}>
              <CardHeader>
                <CardTitle className="hw-mono flex items-center gap-2 text-[13px] uppercase tracking-wide text-muted-foreground">
                  <Target className="h-4 w-4 text-rose-500" /> Priorizadas por riesgo (empieza por aquí)
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-border/60 text-left text-xs text-muted-foreground">
                        <th className="pb-2 pr-3 font-medium">Prioridad</th>
                        <th className="pb-2 pr-3 font-medium">CVE</th>
                        <th className="pb-2 pr-3 font-medium">Señales</th>
                        <th className="pb-2 pr-3 font-medium">CVSS</th>
                        <th className="pb-2 pr-3 font-medium">Activos</th>
                        <th className="pb-2 font-medium">Descripción</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.priorizadas.map((p) => {
                        const band = priorityBand(p.priority, p.inKev);
                        return (
                          <tr key={p.cve} className="border-b border-border/30 align-top last:border-0">
                            <td className="py-2 pr-3">
                              <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold ${band.cls}`}>{band.label}</span>
                              <span className="ml-1 text-[10px] text-muted-foreground/60 tabular-nums">{p.priority}</span>
                            </td>
                            <td className="py-2 pr-3">
                              <a href={`https://cti.wazuh.com/vulnerabilities/cves/${p.cve}`} target="_blank" rel="noreferrer" className="font-mono text-xs text-neon hover:underline">{p.cve}</a>
                            </td>
                            <td className="py-2 pr-3">
                              <div className="flex items-center gap-1.5">
                                <SevChip s={p.severity} />
                                {p.inKev && <KevBadge />}
                                <EpssTag epss={p.epss} />
                              </div>
                            </td>
                            <td className="py-2 pr-3 tabular-nums text-muted-foreground">{p.score ?? '—'}</td>
                            <td className="py-2 pr-3 tabular-nums text-muted-foreground">{p.agentes || p.instancias}</td>
                            <td className="py-2 max-w-sm truncate text-xs text-muted-foreground" title={p.description}>{p.description}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
                <p className="mt-2 text-[11px] text-muted-foreground/70">
                  Prioridad = CVSS + explotación activa (CISA KEV) + probabilidad EPSS. <b>KEV</b> = explotada hoy en el mundo → atender primero, aunque su CVSS no sea el más alto.
                </p>
              </CardContent>
            </Card>
          )}

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
              <CardHeader><CardTitle className="hw-mono text-[13px] uppercase tracking-wide text-muted-foreground">Top CVE (por activos afectados)</CardTitle></CardHeader>
              <CardContent className="space-y-2.5">
                {data.topCve.map((c) => (
                  <div key={c.cve} className="flex items-start gap-2.5">
                    <SevChip s={c.severity} />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <a href={`https://cti.wazuh.com/vulnerabilities/cves/${c.cve}`} target="_blank" rel="noreferrer"
                          className="font-mono text-sm text-neon hover:underline">{c.cve}</a>
                        {c.score != null && <span className="text-[10px] text-muted-foreground">CVSS {c.score}</span>}
                        {c.inKev && <KevBadge />}
                        <EpssTag epss={c.epss} />
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
              <CardHeader><CardTitle className="hw-mono text-[13px] uppercase tracking-wide text-muted-foreground">Vulnerabilidades por activo</CardTitle></CardHeader>
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
            <CardHeader><CardTitle className="hw-mono text-[13px] uppercase tracking-wide text-muted-foreground">Detalle de vulnerabilidades ({data.items.length})</CardTitle></CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border/60 text-left text-xs text-muted-foreground">
                      <th className="pb-2 pr-3 font-medium">CVE</th>
                      <th className="pb-2 pr-3 font-medium">Sev.</th>
                      <th className="pb-2 pr-3 font-medium">CVSS</th>
                      <th className="pb-2 pr-3 font-medium">Riesgo</th>
                      <th className="pb-2 pr-3 font-medium">Paquete</th>
                      <th className="pb-2 pr-3 font-medium">Activo</th>
                      <th className="pb-2 font-medium">Descripción</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.items.map((v, i) => (
                      <tr key={`${v.cve}-${v.agent}-${v.packageName}-${i}`} className="border-b border-border/30 last:border-0 align-top">
                        <td className="py-2 pr-3">
                          <a href={v.reference?.split(',')[0] || `https://cti.wazuh.com/vulnerabilities/cves/${v.cve}`}
                            target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 font-mono text-xs text-neon hover:underline">
                            {v.cve}<ExternalLink className="h-3 w-3" />
                          </a>
                        </td>
                        <td className="py-2 pr-3"><SevChip s={v.severity} /></td>
                        <td className="py-2 pr-3 tabular-nums text-muted-foreground">{v.score ?? '—'}</td>
                        <td className="py-2 pr-3">
                          <div className="flex items-center gap-1.5">
                            {v.inKev && <KevBadge />}
                            <EpssTag epss={v.epss} />
                            {!v.inKev && v.epss == null && <span className="text-[10px] text-muted-foreground/40">—</span>}
                          </div>
                        </td>
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
