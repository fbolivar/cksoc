/**
 * Panel "Salud del SIEM": vigila la propia plataforma Wazuh (agentes, manager,
 * indexer, disco, flujo de alertas). Semaforo global + tarjetas por componente
 * + historico de incidentes de salud. Se actualiza solo cada 30 s.
 */
import { useEffect, useState, useCallback } from 'react';
import {
  HeartPulse, RefreshCw, Server, Database, HardDrive, Activity, Cpu,
  CheckCircle2, AlertTriangle, XCircle, Clock,
} from 'lucide-react';
import { healthApi, type SiemHealth, type HealthEvent, type Estado, type HealthComponent } from '@/lib/health';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

const ICONS: Record<string, typeof Server> = {
  agentes: Cpu, manager: Server, indexer: Database, disco: HardDrive, flujo: Activity,
};

const DOT: Record<Estado, string> = { ok: 'bg-emerald-500', warn: 'bg-amber-500', fail: 'bg-red-500' };
const TEXT: Record<Estado, string> = { ok: 'text-emerald-400', warn: 'text-amber-400', fail: 'text-red-400' };
const RING: Record<Estado, string> = {
  ok: 'border-emerald-500/30', warn: 'border-amber-500/40', fail: 'border-red-500/50',
};
const LABEL: Record<Estado, string> = { ok: 'Operativo', warn: 'Advertencia', fail: 'Fallo' };

const SEM = {
  verde: { bg: 'from-emerald-600/20 to-emerald-500/5', border: 'border-emerald-500/40', dot: 'bg-emerald-500', txt: 'Todos los sistemas operativos', icon: CheckCircle2, ic: 'text-emerald-400' },
  amarillo: { bg: 'from-amber-600/20 to-amber-500/5', border: 'border-amber-500/40', dot: 'bg-amber-500', txt: 'Advertencias detectadas', icon: AlertTriangle, ic: 'text-amber-400' },
  rojo: { bg: 'from-red-600/25 to-red-500/5', border: 'border-red-500/50', dot: 'bg-red-500 animate-pulse', txt: 'Fallo en el SIEM — requiere atención', icon: XCircle, ic: 'text-red-400' },
};

function EstadoChip({ e }: { e: Estado }) {
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-medium ${TEXT[e]}`}>
      <span className={`h-2 w-2 rounded-full ${DOT[e]}`} /> {LABEL[e]}
    </span>
  );
}

function DiskBar({ comp }: { comp: HealthComponent }) {
  const pct = Number(comp.resumen.match(/(\d+)%/)?.[1] ?? 0);
  const color = comp.estado === 'fail' ? 'bg-red-500' : comp.estado === 'warn' ? 'bg-amber-500' : 'bg-emerald-500';
  return (
    <div className="mt-3">
      <div className="h-2 w-full overflow-hidden rounded-full bg-secondary">
        <div className={`h-full ${color} transition-all`} style={{ width: `${Math.min(pct, 100)}%` }} />
      </div>
      <div className="mt-1 text-[11px] text-muted-foreground">{pct}% de uso · umbral 80% / 90%</div>
    </div>
  );
}

export default function SiemHealth() {
  const [health, setHealth] = useState<SiemHealth | null>(null);
  const [eventos, setEventos] = useState<HealthEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (force = false) => {
    try {
      const [h, ev] = await Promise.all([healthApi.siem(force), healthApi.history(40)]);
      setHealth(h);
      setEventos(ev);
      setError(null);
    } catch {
      setError('No se pudo consultar la salud del SIEM.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(() => load(false), 30_000);
    return () => clearInterval(t);
  }, [load]);

  const sem = health ? SEM[health.semaforo] : SEM.verde;
  const SemIcon = sem.icon;

  return (
    <div className="mx-auto max-w-6xl space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
            <HeartPulse className="h-6 w-6 text-neon" /> Salud del SIEM
          </h1>
          <p className="text-sm text-muted-foreground">
            Vigila la propia plataforma Wazuh — “quién vigila al vigilante”
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => { setRefreshing(true); load(true); }} disabled={refreshing}>
          <RefreshCw className={`h-4 w-4 ${refreshing ? 'animate-spin' : ''}`} /> Actualizar
        </Button>
      </div>

      {error && (
        <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {error}
        </div>
      )}

      {/* Semaforo global */}
      {health && (
        <div className={`rounded-xl border ${sem.border} bg-gradient-to-br ${sem.bg} px-5 py-4`}>
          <div className="flex items-center gap-4">
            <SemIcon className={`h-9 w-9 ${sem.ic}`} />
            <div className="flex-1">
              <div className="flex items-center gap-2">
                <span className={`h-3 w-3 rounded-full ${sem.dot}`} />
                <span className="text-lg font-semibold">{sem.txt}</span>
              </div>
              <p className="text-xs text-muted-foreground">
                Última verificación: {new Date(health.generadoEn).toLocaleTimeString('es-CO')} · se actualiza cada 30 s
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Tarjetas por componente */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {(health?.componentes ?? []).map((c) => {
          const Icon = ICONS[c.id] ?? Server;
          return (
            <Card key={c.id} className={`border ${RING[c.estado]}`}>
              <CardContent className="p-4">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-2">
                    <Icon className="h-5 w-5 text-muted-foreground" />
                    <span className="font-medium">{c.nombre}</span>
                  </div>
                  <EstadoChip e={c.estado} />
                </div>
                <p className="mt-2 text-sm">{c.resumen}</p>
                {c.id === 'disco' && <DiskBar comp={c} />}
                {c.detalle && <p className={`mt-2 text-xs ${c.estado === 'ok' ? 'text-muted-foreground' : TEXT[c.estado]}`}>{c.detalle}</p>}

                {/* Detalle de agentes */}
                {c.id === 'agentes' && health && (
                  <div className="mt-3 space-y-1.5 border-t border-border/40 pt-3">
                    {health.agentes.map((a) => (
                      <div key={a.id} className="flex items-center gap-2 text-xs">
                        <span className={`h-2 w-2 rounded-full ${DOT[a.estado]}`} />
                        <span className="font-mono text-muted-foreground">{a.name}</span>
                        <span className="ml-auto text-muted-foreground">
                          {a.status === 'active'
                            ? (a.minutosSinReportar != null ? `hace ${a.minutosSinReportar} min` : 'activo')
                            : a.status}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          );
        })}
        {loading && !health && (
          <p className="col-span-full py-10 text-center text-sm text-muted-foreground">Consultando el estado del SIEM…</p>
        )}
      </div>

      {/* Historico / timeline */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-muted-foreground">
            <Clock className="h-4 w-4" /> Histórico de incidentes de salud
          </CardTitle>
        </CardHeader>
        <CardContent>
          {eventos.length === 0 ? (
            <p className="py-6 text-center text-sm text-muted-foreground">
              Sin cambios de estado registrados. Todo ha estado estable.
            </p>
          ) : (
            <div className="space-y-1">
              {eventos.map((ev) => (
                <div key={ev.id} className="flex items-center gap-3 rounded-md px-2 py-1.5 text-sm hover:bg-secondary/40">
                  <span className={`h-2 w-2 shrink-0 rounded-full ${DOT[ev.estado]}`} />
                  <span className="w-40 shrink-0 text-xs text-muted-foreground">
                    {new Date(ev.ts).toLocaleString('es-CO')}
                  </span>
                  <span className="font-medium capitalize">{ev.componente}</span>
                  <span className={`text-xs ${TEXT[ev.estado]}`}>{LABEL[ev.estado]}</span>
                  {ev.detalle && <span className="truncate text-xs text-muted-foreground">— {ev.detalle}</span>}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
