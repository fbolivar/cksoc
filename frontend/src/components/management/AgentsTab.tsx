/** Vista completa de agentes (Wazuh API) — con clasificación de salud y limpieza de fantasmas. */
import { useEffect, useState } from 'react';
import { Server, Monitor, Search, Trash2, AlertTriangle, Loader2 } from 'lucide-react';
import { wazuhApi, AGENT_HEALTH_META, type AgentItem } from '@/lib/wazuh';
import { useAuth } from '@/lib/auth';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';

export function AgentsTab({ onFlash }: { onFlash: (k: 'ok' | 'err', t: string) => void }) {
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';
  const [agents, setAgents] = useState<AgentItem[]>([]);
  const [q, setQ] = useState('');
  const [busy, setBusy] = useState<string | null>(null);

  const load = () => wazuhApi.agents(200).then(setAgents).catch(() => onFlash('err', 'No se pudieron cargar los agentes'));
  useEffect(() => { void load(); /* eslint-disable-next-line */ }, []);

  async function remove(a: AgentItem) {
    if (!confirm(`¿Eliminar el REGISTRO del agente ${a.name} (#${a.id})?\n\n${a.motivo}\n\nEsto borra su inscripción en Wazuh. Si el equipo vuelve, tendría que re-registrarse. No afecta al equipo físico.`)) return;
    setBusy(a.id);
    try {
      await wazuhApi.removeAgent(a.id);
      onFlash('ok', `Registro del agente ${a.name} eliminado.`);
      await load();
    } catch {
      onFlash('err', `No se pudo eliminar el agente ${a.name}.`);
    } finally { setBusy(null); }
  }

  const filtered = agents.filter(
    (a) => a.name.toLowerCase().includes(q.toLowerCase()) || a.ip.includes(q) || a.os.toLowerCase().includes(q.toLowerCase())
  );
  const atencion = agents.filter((a) => a.needsAttention);

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0">
        <CardTitle className="text-muted-foreground">
          Agentes monitoreados ({agents.length})
          {atencion.length > 0 && <span className="ml-2 text-xs font-normal text-amber-600">· {atencion.length} requieren atención</span>}
        </CardTitle>
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
                <th className="pb-2 pr-4 font-medium">Tipo</th>
                <th className="pb-2 pr-4 font-medium">IP</th>
                <th className="pb-2 pr-4 font-medium">Sistema operativo</th>
                <th className="pb-2 pr-4 font-medium">Último contacto</th>
                <th className="pb-2 pr-4 font-medium">Salud</th>
                {isAdmin && <th className="pb-2 font-medium"></th>}
              </tr>
            </thead>
            <tbody>
              {filtered.map((a) => {
                const Icon = /windows/i.test(a.os) ? Monitor : Server;
                const meta = AGENT_HEALTH_META[a.health];
                const lka = a.lastKeepAlive && !a.lastKeepAlive.startsWith('9999') ? new Date(a.lastKeepAlive).toLocaleString('es-CO') : '—';
                return (
                  <tr key={a.id} className="border-b border-border/30 last:border-0" style={a.needsAttention ? { boxShadow: 'inset 3px 0 0 ' + meta.color } : undefined}>
                    <td className="py-2.5 pr-4">
                      <span className="flex items-center gap-2">
                        <Icon className="h-4 w-4 text-muted-foreground" />
                        <span className="font-medium">{a.name}</span>
                        {a.needsAttention && <AlertTriangle className="h-3 w-3" style={{ color: meta.color }} />}
                        <span className="text-[10px] text-muted-foreground/60">#{a.id}</span>
                      </span>
                    </td>
                    <td className="py-2.5 pr-4 text-[11px] uppercase tracking-wide text-muted-foreground">{a.kind}</td>
                    <td className="py-2.5 pr-4 tabular-nums text-muted-foreground">{a.ip}</td>
                    <td className="py-2.5 pr-4 text-muted-foreground">{a.os}</td>
                    <td className="py-2.5 pr-4 text-muted-foreground">{lka}{a.staleDays != null && a.health !== 'ok' ? ` · ${a.staleDays}d` : ''}</td>
                    <td className="py-2.5 pr-4">
                      <span className="inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[11px]" style={{ background: `${meta.color}22`, color: meta.color }} title={a.motivo}>
                        <span className="h-1.5 w-1.5 rounded-full" style={{ background: meta.color }} />
                        {meta.label}
                      </span>
                    </td>
                    {isAdmin && (
                      <td className="py-2.5 text-right">
                        {a.needsAttention && (
                          <button onClick={() => remove(a)} disabled={busy === a.id} title="Eliminar registro del agente (limpiar fantasma/muerto)"
                            className="inline-flex items-center gap-1 rounded border border-input px-2 py-1 text-[11px] text-muted-foreground hover:border-destructive/50 hover:text-destructive disabled:opacity-50">
                            {busy === a.id ? <Loader2 className="h-3 w-3 animate-spin" /> : <Trash2 className="h-3 w-3" />} Eliminar
                          </button>
                        )}
                      </td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {isAdmin && atencion.length > 0 && (
          <p className="mt-3 text-[11px] text-muted-foreground/70">
            «Eliminar» borra solo el <b>registro</b> del agente en Wazuh (útil para fantasmas que nunca conectaron o equipos dados de baja). No toca el equipo; si vuelve, se re-registra.
          </p>
        )}
      </CardContent>
    </Card>
  );
}
