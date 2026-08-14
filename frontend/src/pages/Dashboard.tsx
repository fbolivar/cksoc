/**
 * Dashboard HexWatch (Fase 2).
 * Paneles: KPIs en vivo, severidad, linea de tiempo, top agentes, MITRE,
 * mapa de calor y estado de agentes. Datos reales de Wazuh (Indexer + API).
 * Actualizacion en vivo del total via Socket.io.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { AxiosError } from 'axios';
import {
  ShieldAlert,
  AlertTriangle,
  ServerCog,
  Flame,
  RefreshCw,
  Radio,
  Trash2,
  Building2,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { alertsApi } from '@/lib/alerts';
import {
  wazuhApi,
  intervalFor,
  type TimeRange,
  type AlertsSummary,
  type TimelinePoint,
  type AgentsSummary,
  type SedeBucket,
} from '@/lib/wazuh';
import { getSocket, type LiveMetrics } from '@/lib/socket';
import { MetricCard } from '@/components/dashboard/MetricCard';
import { RangeSelector } from '@/components/dashboard/RangeSelector';
import { SeverityDonut } from '@/components/dashboard/SeverityDonut';
import { TimelineChart } from '@/components/dashboard/TimelineChart';
import { BarList } from '@/components/dashboard/BarList';
import { ActivityHeatmap } from '@/components/dashboard/ActivityHeatmap';
import { SiemHealthStrip } from '@/components/dashboard/SiemHealthStrip';
import { SEVERITY_COLORS, CHART_BLUE, CHART_TEAL, fmt } from '@/components/dashboard/theme';

interface RangeData {
  summary: AlertsSummary;
  timeline: TimelinePoint[];
  topAgents: { agent: string; count: number }[];
  mitre: { technique: string; count: number }[];
}

export default function Dashboard() {
  const [range, setRange] = useState<TimeRange>('24h');
  const [data, setData] = useState<RangeData | null>(null);
  const [heatmap, setHeatmap] = useState<TimelinePoint[]>([]);
  const [agentsSummary, setAgentsSummary] = useState<AgentsSummary | null>(null);
  const [sedes, setSedes] = useState<SedeBucket[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [live, setLive] = useState<LiveMetrics | null>(null);
  const [connected, setConnected] = useState(false);
  const [massDeletes, setMassDeletes] = useState<number | null>(null);

  // Carga de datos dependientes del rango. Guard de secuencia: al cambiar de
  // rango rapidamente, solo la ultima carga escribe el estado, evitando que una
  // respuesta lenta de un rango anterior pise las metricas del rango vigente.
  const rangeSeq = useRef(0);
  const loadRange = useCallback(async (r: TimeRange) => {
    const my = ++rangeSeq.current;
    setLoading(true);
    setError(null);
    try {
      const [summary, timeline, topAgents, mitre] = await Promise.all([
        wazuhApi.summary(r),
        wazuhApi.timeline(r, intervalFor(r)),
        wazuhApi.topAgents(r),
        wazuhApi.mitre(r),
      ]);
      if (my === rangeSeq.current) setData({ summary, timeline, topAgents, mitre });
    } catch (err) {
      const ax = err as AxiosError<{ error?: string }>;
      if (my === rangeSeq.current) setError(ax.response?.data?.error ?? 'No se pudieron cargar las métricas de Wazuh');
    } finally {
      if (my === rangeSeq.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadRange(range);
  }, [range, loadRange]);

  // Datos independientes del rango (una sola vez)
  useEffect(() => {
    wazuhApi.timeline('7d', '1h').then(setHeatmap).catch(() => undefined);
    wazuhApi.agentsSummary().then(setAgentsSummary).catch(() => undefined);
    wazuhApi.agentsBySede().then(setSedes).catch(() => setSedes(null));
    // Borrado MASIVO en repos protegidos (regla 100215: >=15 archivos/60s por usuario).
    // Es la senal accionable real; los guardados sueltos de Office ya no cuentan aqui.
    alertsApi.search({ range: '24h', ruleId: '100215', page: 0, size: 1 })
      .then((res) => setMassDeletes(res.total)).catch(() => setMassDeletes(null));
  }, []);

  // Socket.io: total en vivo
  useEffect(() => {
    const socket = getSocket();
    const onConnect = () => setConnected(true);
    const onDisconnect = () => setConnected(false);
    const onMetrics = (m: LiveMetrics) => setLive(m);
    socket.on('connect', onConnect);
    socket.on('disconnect', onDisconnect);
    socket.on('metrics:update', onMetrics);
    // El socket es un singleton: si ya estaba conectado al montar, el evento
    // 'connect' no se vuelve a disparar. Inicializa el estado desde el socket.
    if (socket.connected) setConnected(true);
    return () => {
      socket.off('connect', onConnect);
      socket.off('disconnect', onDisconnect);
      socket.off('metrics:update', onMetrics);
    };
  }, []);

  // El total en vivo solo aplica al rango 24h
  const liveTotal = range === '24h' && live ? live.total : data?.summary.total ?? 0;
  const bands = data?.summary.byBand;
  const criticas = bands ? bands.critica : 0;
  const altasCriticas = bands ? bands.alta + bands.critica : 0;

  return (
    <div className="mx-auto max-w-7xl space-y-5">
      {/* Encabezado + controles */}
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="hw-mono text-2xl font-bold tracking-tight">Panel de seguridad</h1>
          <p className="flex items-center gap-2 text-sm text-muted-foreground">
            Postura de seguridad · Integración Wazuh
            <span
              className="inline-flex items-center gap-1 text-[11px]"
              style={{ color: connected ? 'hsl(var(--neon-green))' : '#9ca3af' }}
            >
              <Radio className="h-3 w-3" />
              {connected ? 'En vivo' : 'Sin conexión en vivo'}
            </span>
          </p>
        </div>
        <div className="flex items-center gap-2">
          <RangeSelector value={range} onChange={setRange} />
          <Button variant="outline" size="sm" onClick={() => loadRange(range)} disabled={loading}>
            <RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} />
            Actualizar
          </Button>
        </div>
      </div>

      {error && (
        <Card>
          <CardContent className="flex items-start gap-3 p-4">
            <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-400" />
            <div className="text-sm">
              <p className="font-medium text-amber-700">No se pudieron cargar las métricas</p>
              <p className="mt-1 text-muted-foreground">{error}</p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* KPIs */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          title={`Alertas · ${range}`}
          value={liveTotal}
          icon={ShieldAlert}
          live={range === '24h' && connected}
          subtitle="eventos registrados"
        />
        <MetricCard
          title="Alta + Crítica"
          value={altasCriticas}
          icon={Flame}
          accent={SEVERITY_COLORS.alta}
          subtitle="requieren atención"
        />
        <MetricCard
          title="Críticas"
          value={criticas}
          icon={AlertTriangle}
          accent={SEVERITY_COLORS.critica}
          subtitle="nivel 12+"
        />
        <MetricCard
          title="Agentes activos"
          value={agentsSummary ? `${agentsSummary.active}/${agentsSummary.total}` : '—'}
          icon={ServerCog}
          accent={CHART_BLUE}
          subtitle="monitoreados"
        />
      </div>

      {/* Borrado MASIVO en repos protegidos (regla 100215) — destacado, clic para ver en Alertas */}
      <Link to="/alertas?ruleId=100215" className="block">
        <Card className="border-rose-500/30 bg-rose-500/[0.04] transition hover:bg-rose-500/[0.09]">
          <CardContent className="flex items-center justify-between gap-3 p-4">
            <div className="flex items-center gap-3">
              <span className="flex h-10 w-10 items-center justify-center rounded-lg bg-rose-500/15">
                <Trash2 className="h-5 w-5 text-rose-600" />
              </span>
              <div>
                <p className="text-sm font-semibold">Borrado masivo en repositorios protegidos</p>
                <p className="text-xs text-muted-foreground">≥15 archivos eliminados en 60 s por un usuario · últimas 24 h · 0 = sin incidentes</p>
              </div>
            </div>
            <span className="text-3xl font-bold tabular-nums text-rose-600">{massDeletes ?? '—'}</span>
          </CardContent>
        </Card>
      </Link>

      {/* Timeline + Severidad */}
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2">
          {data && <TimelineChart data={data.timeline} range={range} />}
        </div>
        <div>{bands && <SeverityDonut bands={bands} />}</div>
      </div>

      {/* Top agentes + MITRE */}
      <div className="grid gap-4 lg:grid-cols-2">
        {data && (
          <BarList
            title="Top agentes por alertas"
            color={CHART_BLUE}
            data={data.topAgents.map((a) => ({ label: a.agent, value: a.count }))}
          />
        )}
        {data && (
          <BarList
            title="Top técnicas MITRE ATT&CK"
            color={CHART_TEAL}
            emptyText="Sin técnicas MITRE en este rango"
            data={data.mitre.map((m) => ({ label: m.technique, value: m.count }))}
          />
        )}
      </div>

      {/* Agentes por sede (grupo de Wazuh como dimension de ubicacion) */}
      {sedes && sedes.length > 0 && (
        <Card>
          <CardContent className="p-4">
            <div className="mb-3 flex items-center gap-2">
              <Building2 className="h-4 w-4 text-muted-foreground" />
              <p className="text-sm font-semibold">Agentes por sede</p>
              <span className="text-[11px] text-muted-foreground">· activos / total</span>
            </div>
            <div className="space-y-2">
              {sedes.map((s) => {
                const maxTotal = Math.max(1, ...sedes.map((x) => x.total));
                const offline = s.total - s.active;
                return (
                  <div key={s.sede} className="flex items-center gap-3">
                    <span className="w-40 shrink-0 truncate text-xs" title={s.sede}>{s.sede}</span>
                    <div className="relative h-4 flex-1 overflow-hidden rounded bg-secondary/40">
                      <span className="absolute inset-y-0 left-0 rounded" style={{ width: `${(s.active / maxTotal) * 100}%`, background: CHART_TEAL }} />
                      {offline > 0 && (
                        <span className="absolute inset-y-0 rounded-r bg-muted-foreground/30"
                          style={{ left: `${(s.active / maxTotal) * 100}%`, width: `${(offline / maxTotal) * 100}%` }} />
                      )}
                    </div>
                    <span className="w-16 shrink-0 text-right text-xs tabular-nums text-muted-foreground">
                      <span className="font-semibold text-foreground">{s.active}</span>/{s.total}
                    </span>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Mapa de calor */}
      {heatmap.length > 0 && <ActivityHeatmap data={heatmap} />}

      {/* Salud de la plataforma (resumen — el detalle vive en Salud del SIEM) */}
      <SiemHealthStrip />

      <p className="pb-2 text-center text-[11px] text-muted-foreground/50">
        {data ? `${fmt(data.summary.total)} alertas en el rango seleccionado` : ''}
      </p>
    </div>
  );
}
