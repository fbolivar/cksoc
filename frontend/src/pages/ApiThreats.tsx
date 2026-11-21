/**
 * Amenazas de API — scorecard OWASP API Security Top 10 (2023), construido por
 * correlación de las detecciones de HexWatch (DDoS/Bots + Exposición de APIs).
 * Cada categoría se marca Detectado / Limpio / Sin cobertura (requiere logs HTTP).
 */
import { useCallback, useEffect, useState } from 'react';
import type { AxiosError } from 'axios';
import { Link } from 'react-router-dom';
import { ShieldAlert, Loader2, ExternalLink, CheckCircle2, AlertTriangle, MinusCircle } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { apiThreatsApi, EST_COLOR, EST_LABEL, SEV_COLOR, type ApiThreatsReport, type Estado } from '@/lib/apiThreats';

const RANGES = [
  { v: '1h', l: '1 h' }, { v: '24h', l: '24 h' }, { v: '7d', l: '7 d' },
];

function EstadoIcon({ estado }: { estado: Estado }) {
  if (estado === 'detectado') return <AlertTriangle className="h-4 w-4" style={{ color: EST_COLOR.detectado }} />;
  if (estado === 'limpio') return <CheckCircle2 className="h-4 w-4" style={{ color: EST_COLOR.limpio }} />;
  return <MinusCircle className="h-4 w-4" style={{ color: EST_COLOR['sin-cobertura'] }} />;
}

export default function ApiThreats() {
  const [data, setData] = useState<ApiThreatsReport | null>(null);
  const [range, setRange] = useState('24h');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (r: string) => {
    setLoading(true); setError(null);
    try { setData(await apiThreatsApi.get(r)); }
    catch (e) { setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo cargar'); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { void load(range); }, [load, range]);

  const r = data;
  return (
    <div className="mx-auto max-w-6xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 hw-mono text-2xl font-bold tracking-tight"><ShieldAlert className="h-6 w-6 text-neon" /> Amenazas de API</h1>
          <p className="max-w-3xl text-sm text-muted-foreground">Scorecard OWASP API Security Top 10 (2023) construido por correlación de lo que HexWatch ya detecta a nivel de red y perímetro: DDoS/Bots (SonicWall) y Exposición de APIs (ASM). Las categorías que exigen inspección del payload HTTP se marcan "sin cobertura".</p>
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

      {r && (
        <>
          <div className="grid grid-cols-3 gap-3">
            <Card><CardContent className="p-3"><div className="text-xs text-muted-foreground">Categorías con detección</div><div className="hw-mono text-2xl font-bold" style={{ color: r.resumen.detectadas ? EST_COLOR.detectado : EST_COLOR.limpio }}>{r.resumen.detectadas}</div></CardContent></Card>
            <Card><CardContent className="p-3"><div className="text-xs text-muted-foreground">Limpias / monitoreadas</div><div className="hw-mono text-2xl font-bold" style={{ color: EST_COLOR.limpio }}>{r.resumen.limpias}</div></CardContent></Card>
            <Card><CardContent className="p-3"><div className="text-xs text-muted-foreground">Sin cobertura (req. logs HTTP)</div><div className="hw-mono text-2xl font-bold" style={{ color: EST_COLOR['sin-cobertura'] }}>{r.resumen.sinCobertura}</div></CardContent></Card>
          </div>

          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            {r.categorias.map((c) => (
              <Card key={c.id} className="overflow-hidden" style={{ borderLeft: `3px solid ${c.estado === 'detectado' ? SEV_COLOR[c.severidad] : EST_COLOR[c.estado]}` }}>
                <CardContent className="space-y-2 p-3.5">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="flex items-center gap-1.5">
                        <span className="rounded bg-secondary px-1.5 py-0.5 hw-mono text-[10px] font-semibold text-muted-foreground">{c.id}</span>
                        <span className="truncate text-sm font-semibold">{c.nombre}</span>
                      </div>
                    </div>
                    <span className="flex shrink-0 items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase"
                      style={{ color: EST_COLOR[c.estado], backgroundColor: `${EST_COLOR[c.estado]}1a` }}>
                      <EstadoIcon estado={c.estado} />{EST_LABEL[c.estado]}{c.estado === 'detectado' && c.count ? ` · ${c.count}` : ''}
                    </span>
                  </div>
                  <p className="text-xs text-muted-foreground">{c.descripcion}</p>
                  {c.evidencia.length > 0 && (
                    <ul className="space-y-0.5 rounded bg-secondary/40 p-2">
                      {c.evidencia.slice(0, 5).map((ev, i) => (
                        <li key={i} className="hw-mono text-[11px] text-foreground/80">· {ev}</li>
                      ))}
                    </ul>
                  )}
                  <div className="flex items-center justify-between pt-0.5">
                    <span className="text-[10px] text-muted-foreground">{c.fuente}</span>
                    {c.ruta && (
                      <Link to={c.ruta} className="flex items-center gap-0.5 text-[10px] font-medium text-primary hover:underline">
                        ver módulo <ExternalLink className="h-3 w-3" />
                      </Link>
                    )}
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
          <p className="hw-mono text-[10px] text-muted-foreground">Correlación en vivo · generado {new Date(r.generadoEn).toLocaleString()} · rango {r.range}. HexWatch es MDR (no inline en el HTTP del cliente): BOLA/object/function auth (API1/3/5) requieren enviar los access logs del cliente a Wazuh para analítica por endpoint.</p>
        </>
      )}
    </div>
  );
}
