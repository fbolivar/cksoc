/**
 * Registro de Auditoría (solo admin): traza de acciones de usuario en la app,
 * incluidos inicios de sesión y fallidos. Filtros por acción, usuario,
 * resultado, texto y rango de fechas, con paginación.
 */
import { useEffect, useState, useCallback } from 'react';
import { ShieldQuestion, RefreshCw, Search, ChevronLeft, ChevronRight } from 'lucide-react';
import { auditApi, actionLabel, type AuditItem, type AuditQuery } from '@/lib/audit';
import { Input } from '@/components/ui/input';

const PAGE = 50;

function fmt(iso: string): string {
  return new Date(iso).toLocaleString('es-CO', { dateStyle: 'short', timeStyle: 'medium' });
}

export default function Audit() {
  const [items, setItems] = useState<AuditItem[]>([]);
  const [total, setTotal] = useState(0);
  const [resumen, setResumen] = useState<{ sensibles: number; rutina: number }>({ sensibles: 0, rutina: 0 });
  const [sensitiveOnly, setSensitiveOnly] = useState(true);
  const [loading, setLoading] = useState(true);
  const [actions, setActions] = useState<string[]>([]);
  const [page, setPage] = useState(0);
  const [f, setF] = useState<{ action: string; actor: string; result: string; q: string }>({
    action: '', actor: '', result: '', q: '',
  });

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const query: AuditQuery = {
        action: f.action || undefined,
        actor: f.actor || undefined,
        result: f.result || undefined,
        q: f.q || undefined,
        sensitive: sensitiveOnly ? '1' : undefined,
        limit: PAGE,
        offset: page * PAGE,
      };
      const data = await auditApi.list(query);
      setItems(data.items);
      setTotal(data.total);
      setResumen(data.resumen);
    } finally {
      setLoading(false);
    }
  }, [f, page, sensitiveOnly]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    void auditApi.actions().then(setActions).catch(() => {});
  }, []);

  const applyFilter = (patch: Partial<typeof f>) => {
    setPage(0);
    setF((prev) => ({ ...prev, ...patch }));
  };

  const pages = Math.ceil(total / PAGE);

  return (
    <div className="mx-auto max-w-6xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="hw-mono text-2xl font-bold tracking-tight">Auditoría</h1>
          <p className="text-sm text-muted-foreground">
            Quién hizo qué en la plataforma — las acciones sensibles (bloqueos, borrados, cambios de reglas) primero
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[11px] text-muted-foreground">
            <b style={{ color: '#ef4444' }}>{resumen.sensibles}</b> sensibles · {resumen.rutina} de rutina
          </span>
          <button
            onClick={() => { setPage(0); setSensitiveOnly((v) => !v); }}
            title={sensitiveOnly ? 'Mostrando solo acciones consecuentes (bloqueos, borrados, cambios). Clic para incluir logins y consultas.' : 'Mostrando todo, incluidos logins y chats. Clic para ver solo lo sensible.'}
            className={`flex h-8 items-center gap-1.5 rounded-md border px-3 text-xs ${sensitiveOnly ? 'border-brand/50 bg-brand/15 text-brand' : 'border-input bg-background text-muted-foreground'}`}
          >
            {sensitiveOnly ? '◉ Solo sensibles' : '○ Ver todo'}
          </button>
        </div>
      </div>

      {/* Filtros */}
      <div className="glass grid grid-cols-1 gap-3 rounded-lg p-4 sm:grid-cols-2 lg:grid-cols-4">
        <div>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">Acción</label>
          <select
            value={f.action}
            onChange={(e) => applyFilter({ action: e.target.value })}
            className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
          >
            <option value="">Todas</option>
            {actions.map((a) => (
              <option key={a} value={a}>{actionLabel(a)}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">Usuario</label>
          <Input placeholder="correo…" value={f.actor} onChange={(e) => applyFilter({ actor: e.target.value })} />
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">Resultado</label>
          <select
            value={f.result}
            onChange={(e) => applyFilter({ result: e.target.value })}
            className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
          >
            <option value="">Todos</option>
            <option value="ok">Exitoso</option>
            <option value="fail">Fallido</option>
          </select>
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">Buscar</label>
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input className="pl-8" placeholder="IP, objetivo…" value={f.q} onChange={(e) => applyFilter({ q: e.target.value })} />
          </div>
        </div>
      </div>

      {/* Tabla */}
      <div className="glass overflow-hidden rounded-lg">
        <div className="flex items-center justify-between border-b border-border/60 px-4 py-3 text-sm">
          <span className="font-medium">{total} evento{total === 1 ? '' : 's'}</span>
          <button onClick={() => void load()} className="text-muted-foreground hover:text-foreground" title="Refrescar">
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>

        {loading ? (
          <div className="p-8 text-center text-sm text-muted-foreground">Cargando…</div>
        ) : items.length === 0 ? (
          <div className="flex flex-col items-center gap-2 p-10 text-center text-muted-foreground">
            <ShieldQuestion className="h-8 w-8 opacity-50" />
            <p className="text-sm">Sin eventos para los filtros actuales.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border/50 text-left text-xs text-muted-foreground">
                  <th className="px-4 py-2 font-medium">Fecha</th>
                  <th className="px-4 py-2 font-medium">Usuario</th>
                  <th className="px-4 py-2 font-medium">Acción</th>
                  <th className="px-4 py-2 font-medium">Resultado</th>
                  <th className="px-4 py-2 font-medium">IP</th>
                  <th className="px-4 py-2 font-medium">Objetivo</th>
                </tr>
              </thead>
              <tbody>
                {items.map((it) => (
                  <tr key={it.id} className="border-b border-border/30 hover:bg-secondary/40" style={it.sensitivity === 'sensible' ? { boxShadow: 'inset 3px 0 0 #ef4444' } : undefined}>
                    <td className="whitespace-nowrap px-4 py-2 text-xs text-muted-foreground">{fmt(it.createdAt)}</td>
                    <td className="px-4 py-2">{it.actorEmail ?? '—'}</td>
                    <td className="px-4 py-2">
                      <span className="flex items-center gap-1.5">
                        {it.sensitivity === 'sensible' && <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-red-500" title="Acción sensible" />}
                        {actionLabel(it.action)}
                      </span>
                    </td>
                    <td className="px-4 py-2">
                      <span className={`rounded px-1.5 py-0.5 text-[11px] font-medium ${
                        it.result === 'ok' ? 'bg-primary/15 text-primary' : 'bg-destructive/15 text-destructive'
                      }`}>
                        {it.result === 'ok' ? 'OK' : 'Fallido'}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-4 py-2 font-mono text-xs">{it.ip ?? '—'}</td>
                    <td className="max-w-[220px] truncate px-4 py-2 text-xs text-muted-foreground" title={it.target ?? ''}>{it.target ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Paginación */}
        {pages > 1 && (
          <div className="flex items-center justify-between border-t border-border/60 px-4 py-2 text-sm">
            <span className="text-xs text-muted-foreground">Página {page + 1} de {pages}</span>
            <div className="flex gap-1">
              <button
                disabled={page === 0}
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                className="rounded p-1.5 hover:bg-secondary disabled:opacity-40"
              >
                <ChevronLeft className="h-4 w-4" />
              </button>
              <button
                disabled={page >= pages - 1}
                onClick={() => setPage((p) => Math.min(pages - 1, p + 1))}
                className="rounded p-1.5 hover:bg-secondary disabled:opacity-40"
              >
                <ChevronRight className="h-4 w-4" />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
