/**
 * Exposición de APIs — descubrimiento y postura de las APIs expuestas a Internet
 * del cliente (sobre la superficie de ASM): indicadores de API, documentación/
 * especificaciones expuestas (Swagger/OpenAPI, GraphQL, Actuator) y shadow/zombie.
 */
import { useCallback, useEffect, useState } from 'react';
import type { AxiosError } from 'axios';
import { Boxes, Loader2, ScanSearch, AlertTriangle, FileWarning, Ghost } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/lib/auth';
import { apiExposureApi, SEV_COLOR, type ApiExposureReport } from '@/lib/apiExposure';

export default function ApiExposure() {
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';
  const [data, setData] = useState<ApiExposureReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try { setData(await apiExposureApi.get()); }
    catch (e) { setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo cargar'); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  async function scan() {
    setScanning(true); setMsg(null); setError(null);
    try {
      const r = await apiExposureApi.scan();
      setMsg(`Escaneo completo: ${r.hosts} host(s), ${r.apis} API(s), ${r.specs} spec(s) expuesto(s).`);
      await load();
    } catch (e) { setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo escanear'); }
    finally { setScanning(false); }
  }

  const r = data;
  return (
    <div className="mx-auto max-w-6xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 hw-mono text-2xl font-bold tracking-tight"><Boxes className="h-6 w-6 text-neon" /> Exposición de APIs</h1>
          <p className="text-sm text-muted-foreground">Descubrimiento y postura de las APIs expuestas a Internet (sobre la superficie de ASM): indicadores de API, documentación/especificaciones expuestas y shadow/zombie. Mapeado a OWASP API Top 10.</p>
        </div>
        {isAdmin && (
          <Button size="sm" onClick={() => void scan()} disabled={scanning}>
            {scanning ? <><Loader2 className="h-4 w-4 animate-spin" /> Escaneando…</> : <><ScanSearch className="h-4 w-4" /> Escanear ahora</>}
          </Button>
        )}
      </div>

      {error && <Card><CardContent className="p-4 text-sm text-amber-700">{error}</CardContent></Card>}
      {msg && <div className="rounded-md border border-primary/30 bg-primary/10 px-3 py-2 text-xs text-primary">{msg}</div>}
      {loading && !r && <p className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Cargando…</p>}

      {r && (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
            <Card><CardContent className="p-3"><div className="text-xs text-muted-foreground">Hosts analizados</div><div className="hw-mono text-xl font-bold">{r.resumen.total}</div></CardContent></Card>
            <Card><CardContent className="p-3"><div className="text-xs text-muted-foreground">APIs detectadas</div><div className="hw-mono text-xl font-bold text-neon">{r.resumen.apis}</div></CardContent></Card>
            <Card><CardContent className="p-3"><div className="text-xs text-muted-foreground">Specs/docs expuestos</div><div className="hw-mono text-xl font-bold" style={{ color: r.resumen.specsExpuestos ? SEV_COLOR.alta : SEV_COLOR.baja }}>{r.resumen.specsExpuestos}</div></CardContent></Card>
            <Card><CardContent className="p-3"><div className="text-xs text-muted-foreground">Shadow (nuevas)</div><div className="hw-mono text-xl font-bold" style={{ color: r.resumen.nuevos ? SEV_COLOR.media : SEV_COLOR.baja }}>{r.resumen.nuevos}</div></CardContent></Card>
            <Card><CardContent className="p-3"><div className="text-xs text-muted-foreground">Zombie (inactivas)</div><div className="hw-mono text-xl font-bold" style={{ color: r.resumen.zombies ? SEV_COLOR.media : SEV_COLOR.baja }}>{r.resumen.zombies}</div></CardContent></Card>
          </div>

          <Card><CardContent className="p-0">
            <div className="flex items-center justify-between border-b border-border/60 px-4 py-2.5">
              <span className="text-sm font-semibold">Endpoints descubiertos</span>
              <span className="text-xs text-muted-foreground">{r.ultimoScan ? `último escaneo: ${new Date(r.ultimoScan).toLocaleString()}` : 'sin escaneo aún'}</span>
            </div>
            {r.endpoints.length === 0 ? (
              <p className="py-10 text-center text-sm text-muted-foreground">{isAdmin ? 'Sin datos. Pulsa "Escanear ahora" para sondear la superficie de ASM.' : 'Sin datos de exposición de APIs.'}</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead><tr className="border-b border-border/60 text-left text-xs text-muted-foreground">
                    <th className="px-4 py-2 font-medium">Host</th>
                    <th className="px-2 py-2 font-medium">Tipo</th>
                    <th className="px-2 py-2 font-medium">API</th>
                    <th className="px-2 py-2 font-medium">Severidad</th>
                    <th className="px-2 py-2 font-medium">Hallazgos / OWASP</th>
                  </tr></thead>
                  <tbody>
                    {r.endpoints.map((e) => (
                      <tr key={e.id} className="border-b border-border/30 last:border-0 hover:bg-secondary/40 align-top">
                        <td className="whitespace-nowrap px-4 py-2"><div className="font-mono text-xs">{e.scheme}://{e.host}</div><div className="text-[10px] text-muted-foreground">{e.ip ?? ''}</div></td>
                        <td className="px-2 py-2 text-xs">{e.tipo}{e.specExpuesto && <FileWarning className="ml-1 inline h-3 w-3 text-red-500" />}</td>
                        <td className="px-2 py-2">{e.esApi ? <span className="rounded bg-primary/15 px-1.5 py-0.5 text-[10px] text-primary">API</span> : <span className="text-[10px] text-muted-foreground">web</span>}</td>
                        <td className="px-2 py-2"><span className="rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase text-white" style={{ backgroundColor: SEV_COLOR[e.severidad] }}>{e.severidad}</span></td>
                        <td className="px-2 py-2">
                          {e.hallazgos.length === 0 ? <span className="text-xs text-muted-foreground">—</span> : (
                            <ul className="space-y-1">
                              {e.hallazgos.map((h, i) => (
                                <li key={i} className="flex items-start gap-1.5 text-xs">
                                  <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" style={{ color: SEV_COLOR[h.severidad] }} />
                                  <span>{h.titulo} <span className="rounded bg-primary/10 px-1 text-[10px] text-primary">{h.owasp.split(':')[0]}</span></span>
                                </li>
                              ))}
                            </ul>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent></Card>
          <p className="hw-mono flex items-center gap-1 text-[10px] text-muted-foreground"><Ghost className="h-3 w-3" /> Escaneo activo ACOTADO a los dominios autorizados del cliente (asm_domains), solo GET/introspección. Lo inline (validación de esquema, PII en respuestas) requiere enviar los logs HTTP del cliente a HexWatch.</p>
        </>
      )}
    </div>
  );
}
