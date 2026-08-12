/**
 * Dashboard HexWatch (Fase 2).
 * Paneles: KPIs en vivo, severidad, linea de tiempo, top agentes, MITRE,
 * mapa de calor y estado de agentes. Datos reales de Wazuh (Indexer + API).
 * Actualizacion en vivo del total via Socket.io.
 */
import { useCallback, useEffect, useState } from 'react';
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
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [live, setLive] = useState<LiveMetrics | null>(null);
  const [connected, setConnected] = useState(false);
  const [repoDeletes, setRepoDeletes] = useState<number | null>(null);

  // Carga de datos dependientes del rango
  const loadRange = useCallback(async (r: TimeRange) => {
    setLoading(true);
    setError(null);
    try {
      const [summary, timeline, topAgents, mitre] = await Promise.all([
        wazuhApi.summary(r),
        wazuhApi.timeline(r, intervalFor(r)),
        wazuhApi.topAgents(r),
        wazuhApi.mitre(r),
      ]);
      setData({ summary, timeline, topAgents, mitre });
    } catch (err) {
      const ax = err as AxiosError<{ error?: string }>;
      setError(ax.response?.data?.error ?? 'No se pudieron cargar las métricas de Wazuh');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadRange(range);
  }, [range, loadRange]);

  // Datos independientes del rango (una sola vez)
  useEffect(() => {
    wazuhApi.timeline('7d', '1h').then(setHeatmap).catch(() => undefined);
    wazuhApi.agentsSummary().then(setAgentsSummary).catch(() => undefined);
    // Borrados en repositorios protegidos (auditoria Windows, regla 100210) del dia.
    alertsApi.search({ range: '24h', ruleId: '100210', page: 0, size: 1 })
      .then((res) => setRepoDeletes(res.total)).catch(() => setRepoDeletes(null));
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
          <h1 className="text-2xl font-semibold tracking-tight">Panel de seguridad</h1>
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

      {/* Borrados en repositorios protegidos (auditoria) — destacado, clic para ver en Alertas */}
      <Link to="/alertas?ruleId=100210" className="block">
        <Card className="border-rose-500/30 bg-rose-500/[0.04] transition hover:bg-rose-500/[0.09]">
          <CardContent className="flex items-center justify-between gap-3 p-4">
            <div className="flex items-center gap-3">
              <span className="flex h-10 w-10 items-center justify-center rounded-lg bg-rose-500/15">
                <Trash2 className="h-5 w-5 text-rose-600" />
              </span>
              <div>
                <p className="text-sm font-semibold">Borrados en repositorios protegidos</p>
                <p className="text-xs text-muted-foreground">Auditoría de eliminación de archivos · últimas 24 h · clic para ver el detalle</p>
              </div>
            </div>
            <span className="text-3xl font-bold tabular-nums text-rose-600">{repoDeletes ?? '—'}</span>
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
