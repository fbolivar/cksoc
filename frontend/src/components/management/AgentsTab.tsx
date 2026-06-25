/** Vista completa de agentes (Wazuh API). */
import { useEffect, useState } from 'react';
import { Server, Monitor, Search } from 'lucide-react';
import { wazuhApi, type AgentItem } from '@/lib/wazuh';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';

export function AgentsTab({ onFlash }: { onFlash: (k: 'ok' | 'err', t: string) => void }) {
  const [agents, setAgents] = useState<AgentItem[]>([]);
  const [q, setQ] = useState('');

  useEffect(() => {
    wazuhApi.agents(200).then(setAgents).catch(() => onFlash('err', 'No se pudieron cargar los agentes'));
  }, []);

  const filtered = agents.filter(
    (a) =>
      a.name.toLowerCase().includes(q.toLowerCase()) ||
      a.ip.includes(q) ||
      a.os.toLowerCase().includes(q.toLowerCase())
  );

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0">
        <CardTitle className="text-muted-foreground">Agentes monitoreados ({agents.length})</CardTitle>
        <div className="relative w-56">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Buscar…" className="pl-8 h-9" />
        </div>
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
                <th className="pb-2 pr-4 font-medium">Último contacto</th>
                <th className="pb-2 font-medium">Estado</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((a) => {
                const Icon = /windows/i.test(a.os) ? Monitor : Server;
                const active = a.status === 'active';
                const lka =
                  a.lastKeepAlive && !a.lastKeepAlive.startsWith('9999')
                    ? new Date(a.lastKeepAlive).toLocaleString('es-CO')
                    : '—';
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
                    <td className="py-2.5 pr-4 text-muted-foreground">{lka}</td>
                    <td className="py-2.5">
                      <span
                        className="inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[11px]"
                        style={{
                          background: active ? 'rgba(22,163,74,0.15)' : 'rgba(239,68,68,0.15)',
                          color: active ? '#4ade80' : '#f87171',
                        }}
                      >
                        <span className="h-1.5 w-1.5 rounded-full" style={{ background: active ? '#4ade80' : '#f87171' }} />
                        {active ? 'Activo' : a.status}
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
