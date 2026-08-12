/**
 * Asset 360: lista de activos y vista consolidada de cada uno (estado, alertas,
 * vulnerabilidades, hardening, integridad e inventario en una sola pantalla).
 */
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { AxiosError } from 'axios';
import { Server, RefreshCw, Loader2, ArrowLeft, ShieldAlert, ClipboardCheck, FileSearch, Cpu, ListFilter } from 'lucide-react';
import { assetsApi, type AssetListItem, type AssetDetail } from '@/lib/assets';
import { scoreColor } from '@/lib/sca';
import { downloadCsv, fileStamp, type CsvCol } from '@/lib/csv';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { ExportButton } from '@/components/shared/ExportButton';

const STATUS_DOT: Record<string, string> = { active: 'bg-emerald-500', disconnected: 'bg-red-500', never_connected: 'bg-gray-500', pending: 'bg-amber-500' };

const ASSET_COLS: CsvCol<AssetListItem>[] = [
  { label: 'Nombre', get: (a) => a.name },
  { label: 'IP', get: (a) => a.ip },
  { label: 'Sistema operativo', get: (a) => a.os },
  { label: 'Estado', get: (a) => a.status },
  { label: 'Versión agente', get: (a) => a.version },
  { label: 'Último keep-alive', get: (a) => a.lastKeepAlive ?? '' },
];

export default function Assets() {
  const [list, setList] = useState<AssetListItem[] | null>(null);
  const [sel, setSel] = useState<string | null>(null);
  const [detail, setDetail] = useState<AssetDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    assetsApi.list().then(setList).catch((e) => setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo listar activos')).finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (!sel) { setDetail(null); return; }
    setLoadingDetail(true);
    assetsApi.get(sel).then(setDetail).catch(() => setDetail(null)).finally(() => setLoadingDetail(false));
  }, [sel]);

  return (
    <div className="mx-auto max-w-7xl space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
            <Server className="h-6 w-6 text-neon" /> Activos (Asset 360)
          </h1>
          <p className="text-sm text-muted-foreground">Todo sobre cada servidor en una sola vista</p>
        </div>
        {sel ? (
          <Button variant="outline" size="sm" onClick={() => setSel(null)}><ArrowLeft className="h-4 w-4" /> Volver</Button>
        ) : (
          <div className="flex items-center gap-2">
            <ExportButton onExport={() => downloadCsv(`activos-${fileStamp()}.csv`, list ?? [], ASSET_COLS)} disabled={!list || list.length === 0} />
            <Button variant="outline" size="sm" onClick={() => { setLoading(true); assetsApi.list().then(setList).finally(() => setLoading(false)); }} disabled={loading}>
              <RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} /> Actualizar
            </Button>
          </div>
        )}
      </div>

      {error && <Card><CardContent className="p-4 text-sm text-amber-700">{error}</CardContent></Card>}

      {/* Lista */}
      {!sel && (loading ? (
        <p className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Cargando activos…</p>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {(list ?? []).map((a) => (
            <button key={a.id} onClick={() => setSel(a.name)} className="text-left">
              <Card className="transition-colors hover:border-primary/40">
                <CardContent className="p-4">
                  <div className="flex items-center gap-2">
                    <span className={`h-2.5 w-2.5 rounded-full ${STATUS_DOT[a.status] ?? 'bg-gray-500'}`} />
                    <span className="font-mono text-sm font-medium">{a.name}</span>
                  </div>
                  <p className="mt-1 truncate text-xs text-muted-foreground">{a.os || '—'}</p>
                  <p className="text-[11px] text-muted-foreground/60">{a.ip} · agente {a.version}</p>
                </CardContent>
              </Card>
            </button>
          ))}
        </div>
      ))}

      {/* Detalle */}
      {sel && (loadingDetail || !detail ? (
        <p className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Cargando {sel}…</p>
      ) : (
        <div className="space-y-4">
          {/* Cabecera del activo */}
          <Card>
            <CardContent className="flex flex-wrap items-center justify-between gap-3 p-4">
              <div className="flex items-center gap-3">
                <span className={`h-3 w-3 rounded-full ${STATUS_DOT[detail.meta.status] ?? 'bg-gray-500'}`} />
                <div>
                  <p className="font-mono text-lg font-semibold">{detail.meta.name}</p>
                  <p className="text-xs text-muted-foreground">{detail.meta.os} · {detail.meta.ip} · agente {detail.meta.version}</p>
                </div>
              </div>
              <Link to="/alertas" className="text-xs text-neon hover:underline inline-flex items-center gap-1"><ListFilter className="h-3.5 w-3.5" /> Ver en el explorador de alertas</Link>
            </CardContent>
          </Card>

          <div className="grid gap-4 lg:grid-cols-2">
            {/* Alertas */}
            <Card>
              <CardHeader><CardTitle className="flex items-center gap-2 text-muted-foreground"><ShieldAlert className="h-4 w-4" /> Alertas (7 días) · {detail.alertas.total7d.toLocaleString('es-CO')}</CardTitle></CardHeader>
              <CardContent className="space-y-2">
                <div className="flex gap-4 text-sm">
                  <span style={{ color: '#ef4444' }}>{detail.alertas.critica} crít.</span>
                  <span style={{ color: '#f97316' }}>{detail.alertas.alta} alta</span>
                  <span style={{ color: '#eab308' }}>{detail.alertas.media} media</span>
                  <span style={{ color: '#22c55e' }}>{detail.alertas.baja} baja</span>
                </div>
                <div className="space-y-1 pt-1">
                  {detail.alertas.topReglas.map((r, i) => (
                    <div key={i} className="flex items-center gap-2 text-xs">
                      <span className="tabular-nums rounded bg-secondary px-1.5 text-[10px] text-muted-foreground">{r.count}</span>
                      <span className="truncate text-muted-foreground">{r.desc}</span>
                    </div>
                  ))}
                  {detail.alertas.topReglas.length === 0 && <p className="text-xs text-muted-foreground/60">Sin alertas en el periodo.</p>}
                </div>
              </CardContent>
            </Card>

            {/* Vulnerabilidades */}
            <Card>
              <CardHeader><CardTitle className="flex items-center gap-2 text-muted-foreground"><ShieldAlert className="h-4 w-4" /> Vulnerabilidades · {detail.vulnerabilidades.total}</CardTitle></CardHeader>
              <CardContent className="space-y-2">
                <div className="flex gap-4 text-sm">
                  <span style={{ color: '#dc2626' }}>{detail.vulnerabilidades.criticas} críticas</span>
                  <span style={{ color: '#f97316' }}>{detail.vulnerabilidades.altas} altas</span>
                </div>
                <div className="space-y-1 pt-1">
                  {detail.vulnerabilidades.top.map((c) => (
                    <a key={c.cve} href={`https://cti.wazuh.com/vulnerabilities/cves/${c.cve}`} target="_blank" rel="noreferrer" className="flex items-center gap-2 text-xs hover:underline">
                      <span className="font-mono text-neon">{c.cve}</span>
                      <span className="text-muted-foreground">{c.severity}{c.score ? ` · CVSS ${c.score}` : ''}</span>
                    </a>
                  ))}
                  {detail.vulnerabilidades.top.length === 0 && <p className="text-xs text-muted-foreground/60">Sin vulnerabilidades.</p>}
                </div>
              </CardContent>
            </Card>

            {/* Hardening */}
            <Card>
              <CardHeader><CardTitle className="flex items-center gap-2 text-muted-foreground"><ClipboardCheck className="h-4 w-4" /> Hardening (CIS)</CardTitle></CardHeader>
              <CardContent>
                {detail.hardening ? (
                  <>
                    <div className="mb-1 flex items-center justify-between text-sm">
                      <span className="truncate text-xs text-muted-foreground">{detail.hardening.policy}</span>
                      <span className="tabular-nums">
                        <span style={{ color: '#22c55e' }}>{detail.hardening.pass} ✓</span> · <span style={{ color: '#ef4444' }}>{detail.hardening.fail} ✗</span> · <b style={{ color: scoreColor(detail.hardening.score) }}>{detail.hardening.score}%</b>
                      </span>
                    </div>
                    <div className="h-2.5 w-full overflow-hidden rounded-full bg-secondary">
                      <div className="h-full" style={{ width: `${detail.hardening.score}%`, background: scoreColor(detail.hardening.score) }} />
                    </div>
                  </>
                ) : <p className="text-xs text-muted-foreground/60">Sin evaluación SCA para este activo.</p>}
              </CardContent>
            </Card>

            {/* Inventario */}
            <Card>
              <CardHeader><CardTitle className="flex items-center gap-2 text-muted-foreground"><Cpu className="h-4 w-4" /> Inventario</CardTitle></CardHeader>
              <CardContent>
                {detail.inventario ? (
                  <div className="grid grid-cols-2 gap-2 text-sm">
                    <span className="text-muted-foreground">CPU</span><span className="text-right text-xs">{detail.inventario.cores} núcleos</span>
                    <span className="text-muted-foreground">RAM</span><span className="text-right">{detail.inventario.ramGB} GB</span>
                    <span className="text-muted-foreground">Software</span><span className="text-right tabular-nums">{detail.inventario.packages}</span>
                    <span className="text-muted-foreground">Puertos escucha</span><span className="text-right tabular-nums">{detail.inventario.ports}</span>
                    <span className="text-muted-foreground">Usuarios</span><span className="text-right tabular-nums">{detail.inventario.users.toLocaleString('es-CO')}</span>
                    <span className="text-muted-foreground">Parches</span><span className="text-right tabular-nums">{detail.inventario.hotfixes}</span>
                  </div>
                ) : <p className="text-xs text-muted-foreground/60">Sin inventario para este activo.</p>}
              </CardContent>
            </Card>
          </div>

          {/* FIM */}
          <Card>
            <CardHeader><CardTitle className="flex items-center gap-2 text-muted-foreground"><FileSearch className="h-4 w-4" /> Integridad de archivos (30 días) · {detail.fim.total30d.toLocaleString('es-CO')}</CardTitle></CardHeader>
            <CardContent className="space-y-2">
              <div className="flex gap-4 text-sm">
                <span style={{ color: '#22c55e' }}>{detail.fim.added} añadidos</span>
                <span style={{ color: '#eab308' }}>{detail.fim.modified} modificados</span>
                <span style={{ color: '#ef4444' }}>{detail.fim.deleted} eliminados</span>
              </div>
              <div className="space-y-1">
                {detail.fim.recientes.map((c, i) => (
                  <div key={i} className="flex items-center gap-2 text-xs">
                    <span className="rounded bg-secondary px-1.5 text-[10px] text-muted-foreground">{c.event}</span>
                    <span className="truncate font-mono text-muted-foreground" title={c.path}>{c.path}</span>
                    {c.user && <span className="ml-auto text-[10px] text-muted-foreground/60">{c.user}</span>}
                  </div>
                ))}
                {detail.fim.recientes.length === 0 && <p className="text-xs text-muted-foreground/60">Sin cambios de integridad.</p>}
              </div>
            </CardContent>
          </Card>
        </div>
      ))}
    </div>
  );
}
