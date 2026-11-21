/**
 * LLM Guardrail — "firewall de prompts" del propio pipeline de IA de HexWatch
 * (Copilot, Dossier de Incidente, explicaciones de tuning). Redacta secretos antes
 * de enviarlos a la nube, detecta prompt-injection/jailbreak y endurece el system.
 */
import { useCallback, useEffect, useState } from 'react';
import type { AxiosError } from 'axios';
import { ShieldCheck, EyeOff, AlertTriangle, Loader2, RefreshCw, Lock } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { llmGuardApi, type GuardStats, type GuardEvent } from '@/lib/llmGuard';

const RANGES = [7, 30, 90];

function Kpi({ label, value, color, sub }: { label: string; value: string | number; color: string; sub?: string }) {
  return (
    <Card><CardContent className="p-3">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="hw-mono text-2xl font-bold" style={{ color }}>{value}</div>
      {sub && <div className="text-[10px] text-muted-foreground">{sub}</div>}
    </CardContent></Card>
  );
}

export default function LlmGuard() {
  const [days, setDays] = useState(30);
  const [stats, setStats] = useState<GuardStats | null>(null);
  const [events, setEvents] = useState<GuardEvent[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (d: number) => {
    setLoading(true); setError(null);
    try {
      const [s, e] = await Promise.all([llmGuardApi.stats(d), llmGuardApi.events(50)]);
      setStats(s); setEvents(e);
    } catch (err) { setError((err as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo cargar el guardrail'); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { void load(days); }, [days, load]);

  const redTypes = stats ? Object.entries(stats.porTipoRedaccion).sort((a, b) => b[1] - a[1]) : [];
  const cats = stats ? Object.entries(stats.porCategoria).sort((a, b) => b[1] - a[1]) : [];

  return (
    <div className="mx-auto max-w-6xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 hw-mono text-2xl font-bold tracking-tight"><ShieldCheck className="h-6 w-6 text-neon" /> LLM Guardrail</h1>
          <p className="text-sm text-muted-foreground">Firewall de prompts del pipeline de IA de HexWatch (Copilot, Dossier, tuning): redacta secretos antes de ir a la nube, detecta prompt‑injection/jailbreak y endurece el system. Mapeado a OWASP Top 10 LLM.</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex overflow-hidden rounded-md border border-border/60">
            {RANGES.map((d) => <button key={d} onClick={() => setDays(d)} className={`px-3 py-1.5 text-xs ${days === d ? 'bg-primary text-primary-foreground' : 'hover:bg-secondary/60'}`}>{d}d</button>)}
          </div>
          <Button variant="outline" size="sm" onClick={() => void load(days)} disabled={loading}><RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} /></Button>
        </div>
      </div>

      {error && <Card><CardContent className="p-4 text-sm text-amber-700">{error}</CardContent></Card>}
      {loading && !stats && <p className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Cargando…</p>}

      {stats && (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            <Kpi label="Llamadas protegidas con evento" value={stats.llamadasProtegidas} color="#14b8a6" sub={`últimos ${stats.dias}d`} />
            <Kpi label="Secretos redactados" value={stats.totalRedacciones} color={stats.totalRedacciones ? '#f59e0b' : '#22c55e'} sub="antes de salir a la nube" />
            <Kpi label="Inyecciones detectadas" value={stats.inyeccionesDetectadas} color={stats.inyeccionesDetectadas ? '#ef4444' : '#22c55e'} sub="prompt‑injection / jailbreak" />
          </div>

          <div className="grid gap-3 md:grid-cols-2">
            <Card><CardContent className="p-4">
              <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground"><EyeOff className="h-4 w-4" /> Secretos redactados por tipo (OWASP LLM06)</h3>
              {redTypes.length === 0 ? <p className="text-xs text-muted-foreground">Sin redacciones en el rango.</p> : (
                <ul className="space-y-1">{redTypes.map(([k, v]) => <li key={k} className="flex justify-between text-sm"><span className="font-mono text-xs">{k}</span><span className="font-semibold tabular-nums">{v}</span></li>)}</ul>
              )}
            </CardContent></Card>
            <Card><CardContent className="p-4">
              <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground"><AlertTriangle className="h-4 w-4" /> Inyección por categoría (OWASP LLM01)</h3>
              {cats.length === 0 ? <p className="text-xs text-muted-foreground">Sin inyecciones detectadas en el rango.</p> : (
                <ul className="space-y-1">{cats.map(([k, v]) => <li key={k} className="flex justify-between text-sm"><span className="text-xs">{k}</span><span className="font-semibold tabular-nums">{v}</span></li>)}</ul>
              )}
            </CardContent></Card>
          </div>

          <Card><CardContent className="p-0">
            <div className="flex items-center gap-2 border-b border-border/60 px-4 py-2.5 text-sm font-semibold"><Lock className="h-4 w-4 text-neon" /> Eventos recientes del guardrail</div>
            {!events || events.length === 0 ? (
              <p className="flex items-center justify-center gap-2 py-8 text-sm text-muted-foreground"><ShieldCheck className="h-4 w-4 text-emerald-500" /> Sin eventos: ninguna llamada reciente requirió redacción ni disparó detección.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead><tr className="border-b border-border/60 text-left text-xs text-muted-foreground">
                    <th className="px-4 py-2 font-medium">Fecha</th>
                    <th className="px-2 py-2 font-medium text-right">Redacciones</th>
                    <th className="px-2 py-2 font-medium text-right">Inyección</th>
                    <th className="px-2 py-2 font-medium">Categorías / OWASP</th>
                    <th className="px-2 py-2 font-medium">Muestra</th>
                  </tr></thead>
                  <tbody>
                    {events.map((e) => (
                      <tr key={e.id} className="border-b border-border/30 last:border-0 hover:bg-secondary/40">
                        <td className="whitespace-nowrap px-4 py-2 text-xs text-muted-foreground">{new Date(e.createdAt).toLocaleString()}</td>
                        <td className="px-2 py-2 text-right tabular-nums">{e.totalRedactions || '—'}</td>
                        <td className="px-2 py-2 text-right"><span className="font-semibold" style={{ color: e.injectionScore ? '#ef4444' : '#6b7280' }}>{e.injectionScore || '—'}</span></td>
                        <td className="px-2 py-2"><div className="flex flex-wrap gap-1">
                          {e.categories.map((c) => <span key={c} className="rounded bg-red-500/10 px-1.5 py-0.5 text-[10px] text-red-500">{c}</span>)}
                          {e.owasp.map((o) => <span key={o} className="rounded bg-primary/10 px-1.5 py-0.5 text-[10px] text-primary">{o.split(':')[0]}</span>)}
                        </div></td>
                        <td className="max-w-xs px-2 py-2"><span className="block truncate font-mono text-[11px] text-muted-foreground">{e.samples[0] ?? ''}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent></Card>
          <p className="hw-mono text-[10px] text-muted-foreground">El guardrail NO bloquea el análisis (un alerta con payload de inyección es justo lo que el analista estudia): sanitiza secretos, endurece el prompt y audita. Solo se registran las llamadas con redacción o detección.</p>
        </>
      )}
    </div>
  );
}
