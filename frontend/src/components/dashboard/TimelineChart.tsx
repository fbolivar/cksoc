import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import type { TimelinePoint, TimeRange } from '@/lib/wazuh';
import { CHART_CORAL, CHART_AXIS, CHART_GRID, fmt, tooltipStyle } from './theme';

function formatTick(ts: string, range: TimeRange): string {
  const d = new Date(ts);
  if (range === '24h') {
    return d.toLocaleTimeString('es-CO', { hour: '2-digit', minute: '2-digit' });
  }
  return d.toLocaleDateString('es-CO', { day: '2-digit', month: '2-digit' });
}

export function TimelineChart({
  data,
  range,
}: {
  data: TimelinePoint[];
  range: TimeRange;
}) {
  const chartData = data.map((p) => ({ ...p, label: formatTick(p.ts, range) }));

  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle className="text-muted-foreground">Línea de tiempo de alertas</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="h-[240px]">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData} margin={{ top: 5, right: 10, left: -10, bottom: 0 }}>
              <defs>
                <linearGradient id="grad-alerts" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={CHART_CORAL} stopOpacity={0.35} />
                  <stop offset="100%" stopColor={CHART_CORAL} stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke={CHART_GRID} vertical={false} />
              <XAxis
                dataKey="label"
                tick={{ fontSize: 11, fill: CHART_AXIS }}
                tickLine={false}
                axisLine={{ stroke: CHART_GRID }}
                interval="preserveStartEnd"
                minTickGap={24}
              />
              <YAxis
                tick={{ fontSize: 11, fill: CHART_AXIS }}
                tickLine={false}
                axisLine={false}
                tickFormatter={(v: number) => (v >= 1000 ? `${Math.round(v / 1000)}k` : String(v))}
                width={42}
              />
              <Tooltip contentStyle={tooltipStyle} formatter={(v: number) => [fmt(v), 'Alertas']} />
              <Area
                type="monotone"
                dataKey="count"
                stroke={CHART_CORAL}
                strokeWidth={2}
                fill="url(#grad-alerts)"
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}
