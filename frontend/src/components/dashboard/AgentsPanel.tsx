import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import { Server, Monitor } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import type { AgentItem, AgentsSummary } from '@/lib/wazuh';
import { fmt, tooltipStyle } from './theme';

const STATUS_COLORS: Record<string, string> = {
  active: '#16a34a',
  disconnected: '#ef4444',
  never_connected: '#6b7280',
  pending: '#eab308',
};

const STATUS_LABELS: Record<string, string> = {
  active: 'Activo',
  disconnected: 'Desconectado',
  never_connected: 'Nunca conectado',
  pending: 'Pendiente',
};

function osIcon(os: string) {
  return /windows/i.test(os) ? Monitor : Server;
}

export function AgentsStatusDonut({ summary }: { summary: AgentsSummary }) {
  const data = [
    { key: 'active', value: summary.active },
    { key: 'disconnected', value: summary.disconnected },
    { key: 'never_connected', value: summary.neverConnected },
    { key: 'pending', value: summary.pending },
  ].filter((d) => d.value > 0);

  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle className="text-muted-foreground">Estado de agentes</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="relative h-[180px]">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                dataKey="value"
                nameKey="key"
                cx="50%"
                cy="50%"
                innerRadius={50}
                outerRadius={75}
                paddingAngle={2}
                stroke="none"
              >
                {data.map((d) => (
                  <Cell key={d.key} fill={STATUS_COLORS[d.key]} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={tooltipStyle}
                formatter={(v: number, _n, p) => [fmt(v), STATUS_LABELS[(p as { payload: { key: string } }).payload.key]]}
              />
            </PieChart>
          </ResponsiveContainer>
          <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-2xl font-bold tabular-nums">{summary.total}</span>
            <span className="text-[11px] text-muted-foreground">agentes</span>
          </div>
        </div>
        <div className="mt-2 space-y-1">
          {Object.entries(STATUS_LABELS).map(([k, label]) => {
            const val =
              k === 'active'
                ? summary.active
                : k === 'disconnected'
                  ? summary.disconnected
                  : k === 'never_connected'
                    ? summary.neverConnected
                    : summary.pending;
            return (
              <div key={k} className="flex items-center gap-2 text-xs">
                <span className="h-2.5 w-2.5 rounded-sm" style={{ background: STATUS_COLORS[k] }} />
                <span className="text-muted-foreground">{label}</span>
                <span className="ml-auto tabular-nums">{val}</span>
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}

export function AgentsTable({ agents }: { agents: AgentItem[] }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-muted-foreground">Agentes monitoreados</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border/60 text-left text-xs text-muted-foreground">
                <th className="pb-2 pr-4 font-medium">Agente</th>
                <th className="pb-2 pr-4 font-medium">IP</th>
                <th className="pb-2 pr-4 font-medium">Sistema operativo</th>
                <th className="pb-2 pr-4 font-medium">Versión</th>
                <th className="pb-2 font-medium">Estado</th>
              </tr>
            </thead>
            <tbody>
              {agents.map((a) => {
                const Icon = osIcon(a.os);
                const active = a.status === 'active';
                return (
                  <tr key={a.id} className="border-b border-border/30 last:border-0">
                    <td className="py-2.5 pr-4">
                      <span className="flex items-center gap-2">
                        <Icon className="h-4 w-4 text-muted-foreground" />
                        <span className="font-medium">{a.name}</span>
                        <span className="text-[10px] text-muted-foreground/60">#{a.id}</span>
                      </span>
                    </td>
                    <td className="py-2.5 pr-4 tabular-nums text-muted-foreground">{a.ip}</td>
                    <td className="py-2.5 pr-4 text-muted-foreground">{a.os}</td>
                    <td className="py-2.5 pr-4 text-muted-foreground">{a.version}</td>
                    <td className="py-2.5">
                      <span
                        className="inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[11px]"
                        style={{
                          background: active ? 'rgba(22,163,74,0.15)' : 'rgba(239,68,68,0.15)',
                          color: active ? '#4ade80' : '#f87171',
                        }}
                      >
                        <span
                          className="h-1.5 w-1.5 rounded-full"
                          style={{ background: active ? '#4ade80' : '#f87171' }}
                        />
                        {STATUS_LABELS[a.status] ?? a.status}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}
