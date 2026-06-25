import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import type { SeverityBands } from '@/lib/wazuh';
import { SEVERITY_COLORS, SEVERITY_LABELS, fmt, tooltipStyle } from './theme';

export function SeverityDonut({ bands }: { bands: SeverityBands }) {
  const data = (Object.keys(SEVERITY_LABELS) as (keyof SeverityBands)[]).map((k) => ({
    key: k,
    name: SEVERITY_LABELS[k],
    value: bands[k],
    color: SEVERITY_COLORS[k],
  }));
  const total = data.reduce((s, d) => s + d.value, 0);

  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle className="text-muted-foreground">Alertas por severidad</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="relative h-[220px]">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={90}
                paddingAngle={2}
                stroke="none"
              >
                {data.map((d) => (
                  <Cell key={d.key} fill={d.color} />
                ))}
              </Pie>
              <Tooltip contentStyle={tooltipStyle} formatter={(v: number) => fmt(v)} />
            </PieChart>
          </ResponsiveContainer>
          <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-2xl font-bold tabular-nums">{fmt(total)}</span>
            <span className="text-[11px] text-muted-foreground">total</span>
          </div>
        </div>
        <div className="mt-2 grid grid-cols-2 gap-2">
          {data.map((d) => (
            <div key={d.key} className="flex items-center gap-2 text-xs">
              <span className="h-2.5 w-2.5 rounded-sm" style={{ background: d.color }} />
              <span className="text-muted-foreground">{d.name}</span>
              <span className="ml-auto tabular-nums">{fmt(d.value)}</span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
