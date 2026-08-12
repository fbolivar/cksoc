/**
 * Resumen Ejecutivo: una sola vista que consolida la postura de todos los
 * dominios del SOC (amenazas, endpoints, cumplimiento, salud del SIEM, agentes),
 * con enlaces a cada modulo de detalle.
 */
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { AxiosError } from 'axios';
import {
  LayoutDashboard, RefreshCw, Loader2, CheckCircle2, AlertTriangle, XCircle,
  Globe2, Bug, ClipboardCheck, FileSearch, Scale, HeartPulse, Server, ChevronRight,
} from 'lucide-react';
import { overviewApi, SEMAFORO_META, type OverviewData } from '@/lib/overview';
import { scoreColor } from '@/lib/sca';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

function DomainCard({
  to, icon: Icon, title, children,
}: { to: string; icon: typeof Globe2; title: string; children: React.ReactNode }) {
  return (
    <Link to={to} className="group block">
      <Card className="h-full transition-colors hover:border-primary/40">
        <CardContent className="p-4">
          <div className="mb-3 flex items-center gap-2">
            <Icon className="h-4 w-4 text-neon" />
            <span className="font-medium">{title}</span>
            <ChevronRight className="ml-auto h-4 w-4 text-muted-foreground/40 transition-transform group-hover:translate-x-0.5" />
          </div>
          {children}
        </CardContent>
      </Card>
    </Link>
  );
}

function Stat({ label, value, color }: { label: string; value: string | number; color?: string }) {
  return (
    <div>
      <p className="text-xl font-semibold tabular-nums" style={color ? { color } : undefined}>{value}</p>
      <p className="text-[11px] text-muted-foreground">{label}</p>
    </div>
  );
}

const DOT: Record<string, string> = { verde: 'bg-emerald-500', amarillo: 'bg-amber-500', rojo: 'bg-red-500' };

export default function Overview() {
  const [d, setD] = useState<OverviewData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    setLoading(true); setError(null);
    try { setD(await overviewApi.get()); }
    catch (e) { setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo cargar el resumen'); }
    finally { setLoading(false); }
  }
  useEffect(() => {
    load();
    const t = setInterval(load, 60_000);
    return () => clearInterval(t);
  }, []);

  const sem = d ? SEMAFORO_META[d.global.semaforo] : SEMAFORO_META.verde;
  const SemIcon = d?.global.semaforo === 'rojo' ? XCircle : d?.global.semaforo === 'amarillo' ? AlertTriangle : CheckCircle2;

  return (
    <div className="mx-auto max-w-7xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
            <LayoutDashboard className="h-6 w-6 text-neon" /> Resumen Ejecutivo
          </h1>
          <p className="text-sm text-muted-foreground">Postura consolidada del SOC en una sola vista</p>
        </div>
        <Button variant="outline" size="sm" onClick={load} disabled={loading}>
          <RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} /> Actualizar
        </Button>
      </div>

      {error && <Card><CardContent className="p-4 text-sm text-amber-700">{error}</CardContent></Card>}

      {loading && !d ? (
        <p className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" /> Consolidando postura…
        </p>
      ) : d && (
        <>
          {/* Postura global */}
          <div className="rounded-xl border px-5 py-4"
            style={{ borderColor: `${sem.color}66`, background: `linear-gradient(135deg, ${sem.color}1f, transparent 70%)` }}>
            <div className="flex items-center gap-4">
              <SemIcon className="h-9 w-9" style={{ color: sem.color }} />
              <div>
                <p className="text-lg font-semibold">Postura global: <span style={{ color: sem.color }}>{sem.label}</span></p>
                <p className="text-sm text-muted-foreground">{d.global.motivo}</p>
              </div>
              <span className="ml-auto text-[11px] text-muted-foreground">
                {new Date(d.generadoEn).toLocaleTimeString('es-CO')} · cada 60 s
              </span>
            </div>
          </div>

          {/* Dominios */}
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            <DomainCard to="/mapa" icon={Globe2} title="Amenazas (24h / 7d)">
              <div className="grid grid-cols-3 gap-2">
                <Stat label="Alertas 24h" value={d.amenazas.alertas24h.toLocaleString('es-CO')} />
                <Stat label="Alta+Crítica" value={d.amenazas.altasCriticas24h.toLocaleString('es-CO')} color="#f97316" />
                <Stat label="Orígenes ext." value={d.amenazas.ataquesExternos} color="#ef4444" />
              </div>
            </DomainCard>

            <DomainCard to="/vulnerabilidades" icon={Bug} title="Vulnerabilidades">
              <div className="grid grid-cols-3 gap-2">
                <Stat label="Críticas" value={d.endpoints.vulnCriticas} color="#dc2626" />
                <Stat label="Altas" value={d.endpoints.vulnAltas} color="#f97316" />
                <Stat label="Total" value={d.endpoints.vulnTotal} />
              </div>
            </DomainCard>

            <DomainCard to="/sca" icon={ClipboardCheck} title="Hardening (CIS)">
              <div className="flex items-end gap-4">
                <Stat label="Cumplimiento promedio" value={`${d.endpoints.hardeningScore}%`} color={scoreColor(d.endpoints.hardeningScore)} />
              </div>
              <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-secondary">
                <div className="h-full" style={{ width: `${d.endpoints.hardeningScore}%`, background: scoreColor(d.endpoints.hardeningScore) }} />
              </div>
            </DomainCard>

            <DomainCard to="/fim" icon={FileSearch} title="Integridad (FIM)">
              <Stat label="Cambios (7 días)" value={d.endpoints.fimCambios.toLocaleString('es-CO')} />
            </DomainCard>

            <DomainCard to="/cumplimiento" icon={Scale} title="Cumplimiento">
              <div className="grid grid-cols-2 gap-x-3 gap-y-1.5">
                {d.cumplimiento.map((c) => (
                  <div key={c.marco} className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">{c.marco}</span>
                    <span className="tabular-nums font-medium">{c.controles}</span>
                  </div>
                ))}
              </div>
            </DomainCard>

            <DomainCard to="/salud" icon={HeartPulse} title="Salud del SIEM">
              <div className="flex items-center gap-3">
                <span className={`h-3 w-3 rounded-full ${DOT[d.siem.semaforo]}`} />
                <Stat label="Componentes OK" value={`${d.siem.ok}/${d.siem.total}`} />
                <div className="ml-auto flex items-center gap-2">
                  <Server className="h-4 w-4 text-muted-foreground" />
                  <Stat label="Agentes" value={`${d.agentes.activos}/${d.agentes.total}`} />
                </div>
              </div>
            </DomainCard>
          </div>

          <p className="text-center text-[11px] text-muted-foreground/60">
            Cada tarjeta enlaza al módulo de detalle. La postura global combina las señales de todos los dominios.
          </p>
        </>
      )}
    </div>
  );
}
