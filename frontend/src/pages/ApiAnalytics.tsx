/**
 * Analítica de API por endpoint (#C) — detecta BOLA / broken-auth / function-level
 * auth REALES desde los logs HTTP (web-accesslog) de los servidores web monitoreados
 * por Wazuh. Hoy la fuente con cobertura es la propia API de HexWatch (auto-defensa
 * + ruta de onboarding: el mismo <localfile> se aplica al web server del cliente).
 */
import { useCallback, useEffect, useState } from 'react';
import type { AxiosError } from 'axios';
import { Activity, Loader2, AlertTriangle, ServerCog, KeyRound } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { apiAnalyticsApi, SEV_COLOR, type ApiAnalyticsReport } from '@/lib/apiAnalytics';

const RANGES = [{ v: '1h', l: '1 h' }, { v: '24h', l: '24 h' }, { v: '7d', l: '7 d' }];
const STATUS_COLOR = (code: string) => (/^2/.test(code) ? '#22c55e' : /^3/.test(code) ? '#64748b' : code === '401' || code === '403' ? '#ef4444' : /^4/.test(code) ? '#f59e0b' : /^5/.test(code) ? '#a855f7' : '#64748b');

export default function ApiAnalytics() {
  const [data, setData] = useState<ApiAnalyticsReport | null>(null);
  const [range, setRange] = useState('24h');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (r: string) => {
    setLoading(true); setError(null);
    try { setData(await apiAnalyticsApi.get(r)); }
    catch (e) { setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo cargar'); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { void load(range); }, [load, range]);

  const r = data;
  return (
    <div className="mx-auto max-w-6xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 hw-mono text-2xl font-bold tracking-tight"><Activity className="h-6 w-6 text-neon" /> Analítica de API</h1>
          <p className="max-w-3xl text-sm text-muted-foreground">Detección por endpoint desde los logs HTTP (web-accesslog) de los servidores web monitoreados: fallos de autenticación (401/403), enumeración de objetos (BOLA) y errores de servidor. Cierra API1/API5 del scorecard OWASP.</p>
        </div>
        <div className="flex items-center gap-1 rounded-md border border-border/60 p-0.5">
          {RANGES.map((x) => (
            <button key={x.v} onClick={() => setRange(x.v)}
              className={`rounded px-2.5 py-1 text-xs font-medium ${range === x.v ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:bg-secondary'}`}>{x.l}</button>
          ))}
        </div>
      </div>

      {error && <Card><CardContent className="p-4 text-sm text-amber-700">{error}</CardContent></Card>}
      {loading && !r && <p className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Cargando…</p>}

      {r && !r.cobertura && (
        <Card><CardContent className="space-y-1 p-4">
          <div className="flex items-center gap-2 text-sm font-semibold"><ServerCog className="h-4 w-4 text-amber-500" /> Sin cobertura de logs HTTP en este rango</div>
          <p className="text-xs text-muted-foreground">Para extender la analítica por endpoint al web server del cliente, añade su <code>access.log</code> como <code>&lt;localfile&gt;</code> en el agente Wazuh de ese host. HexWatch decodificará método, ruta, estado y origen automáticamente.</p>
        </CardContent></Card>
      )}

      {r && r.cobertura && (
        <>
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs text-muted-foreground">Fuentes monitoreadas:</span>
            {r.fuentes.map((f) => (
              <span key={f.name} className="rounded bg-primary/15 px-2 py-0.5 hw-mono text-[11px] text-primary">{f.name} · {f.eventos}</span>
            ))}
          </div>

          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Card><CardContent className="p-3"><div className="text-xs text-muted-foreground">Eventos HTTP</div><div className="hw-mono text-xl font-bold">{r.resumen.eventos}</div></CardContent></Card>
            <Card><CardContent className="p-3"><div className="text-xs text-muted-foreground">Endpoints</div><div className="hw-mono text-xl font-bold">{r.resumen.endpoints}</div></CardContent></Card>
            <Card><CardContent className="p-3"><div className="text-xs text-muted-foreground">Fallos de auth (401/403)</div><div className="hw-mono text-xl font-bold" style={{ color: r.resumen.authFails ? SEV_COLOR.alta : SEV_COLOR.baja }}>{r.resumen.authFails}</div></CardContent></Card>
            <Card><CardContent className="p-3"><div className="text-xs text-muted-foreground">IPs enumerando / 5xx</div><div className="hw-mono text-xl font-bold" style={{ color: (r.resumen.enumeracion || r.resumen.serverErrors) ? SEV_COLOR.media : SEV_COLOR.baja }}>{r.resumen.enumeracion} / {r.resumen.serverErrors}</div></CardContent></Card>
          </div>

          {r.hallazgos.length > 0 && (
            <Card><CardContent className="p-0">
              <div className="border-b border-border/60 px-4 py-2.5 text-sm font-semibold">Hallazgos OWASP por endpoint</div>
              <ul className="divide-y divide-border/40">
                {r.hallazgos.map((h, i) => (
                  <li key={i} className="flex items-start gap-2 px-4 py-2.5">
                    <KeyRound className="mt-0.5 h-4 w-4 shrink-0" style={{ color: SEV_COLOR[h.severidad] }} />
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className="text-sm font-medium">{h.titulo}</span>
                        <span className="rounded bg-primary/10 px-1 text-[10px] text-primary">{h.owasp.split(':')[0]}</span>
                        <span className="rounded px-1 text-[10px] font-semibold text-white" style={{ backgroundColor: h.externa ? '#ef4444' : '#64748b' }}>{h.externa ? 'EXTERNO' : 'interno'}</span>
                      </div>
                      <p className="text-xs text-muted-foreground">{h.detalle}</p>
                      {h.evidencia.length > 0 && <p className="hw-mono text-[11px] text-foreground/70">{h.evidencia.join(' · ')}</p>}
                    </div>
                  </li>
                ))}
              </ul>
            </CardContent></Card>
          )}

          <Card><CardContent className="p-0">
            <div className="border-b border-border/60 px-4 py-2.5 text-sm font-semibold">Endpoints (alertas web 4xx/5xx)</div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead><tr className="border-b border-border/60 text-left text-xs text-muted-foreground">
                  <th className="px-4 py-2 font-medium">Endpoint</th>
                  <th className="px-2 py-2 font-medium">Método</th>
                  <th className="px-2 py-2 font-medium">Hits</th>
                  <th className="px-2 py-2 font-medium">Estados</th>
                  <th className="px-2 py-2 font-medium">IPs</th>
                </tr></thead>
                <tbody>
                  {r.endpoints.map((e, i) => (
                    <tr key={i} className="border-b border-border/30 last:border-0 align-top hover:bg-secondary/40">
                      <td className="px-4 py-2"><span className="hw-mono text-xs" style={{ color: e.flag === 'alta' ? SEV_COLOR.alta : undefined }}>{e.flag === 'alta' && <AlertTriangle className="mr-1 inline h-3 w-3" />}{e.endpoint}</span></td>
                      <td className="px-2 py-2 text-xs text-muted-foreground">{e.metodos.join('/')}</td>
                      <td className="px-2 py-2 hw-mono text-xs">{e.hits}</td>
                      <td className="px-2 py-2">
                        <div className="flex flex-wrap gap-1">
                          {Object.entries(e.status).sort((a, b) => b[1] - a[1]).map(([code, n]) => (
                            <span key={code} className="rounded px-1 text-[10px] font-semibold text-white" style={{ backgroundColor: STATUS_COLOR(code) }}>{code}:{n}</span>
                          ))}
                        </div>
                      </td>
                      <td className="px-2 py-2 hw-mono text-[11px] text-muted-foreground">{e.fuentesIp}{e.topIps.length ? ` · ${e.topIps[0]}` : ''}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent></Card>
          <p className="hw-mono text-[10px] text-muted-foreground">Sobre alertas web de Wazuh (4xx/5xx/escaneo), no sobre cada 200 · generado {new Date(r.generadoEn).toLocaleString()} · rango {r.range}. Onboarding del cliente = añadir su access.log como localfile al agente Wazuh de su web server.</p>
        </>
      )}
    </div>
  );
}
