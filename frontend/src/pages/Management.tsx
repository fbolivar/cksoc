/**
 * Pagina de Gestion (Fase 5).
 * Pestanas: Usuarios (admin), Agentes y Sistema.
 */
import { useState } from 'react';
import { Users, ServerCog, SlidersHorizontal } from 'lucide-react';
import { useAuth } from '@/lib/auth';
import { cn } from '@/lib/utils';
import { UsersTab } from '@/components/management/UsersTab';
import { AgentsTab } from '@/components/management/AgentsTab';
import { SystemTab } from '@/components/management/SystemTab';

type Tab = 'usuarios' | 'agentes' | 'sistema';

export default function Management() {
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';
  const [tab, setTab] = useState<Tab>(isAdmin ? 'usuarios' : 'agentes');
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  const flash = (kind: 'ok' | 'err', text: string) => {
    setMsg({ kind, text });
    setTimeout(() => setMsg(null), 4000);
  };

  const tabs: { id: Tab; label: string; icon: typeof Users; show: boolean }[] = [
    { id: 'usuarios', label: 'Usuarios', icon: Users, show: isAdmin },
    { id: 'agentes', label: 'Agentes', icon: ServerCog, show: true },
    { id: 'sistema', label: 'Sistema', icon: SlidersHorizontal, show: true },
  ];

  return (
    <div className="mx-auto max-w-6xl space-y-5">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Gestión</h1>
        <p className="text-sm text-muted-foreground">Usuarios, agentes y configuración del sistema</p>
      </div>

      {/* Pestanas */}
      <div className="flex gap-1 border-b border-border/60">
        {tabs.filter((t) => t.show).map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={cn(
              'flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors',
              tab === t.id
                ? 'border-primary text-foreground'
                : 'border-transparent text-muted-foreground hover:text-foreground'
            )}
          >
            <t.icon className="h-4 w-4" />
            {t.label}
          </button>
        ))}
      </div>

      {msg && (
        <div
          className={`rounded-md border px-3 py-2 text-sm ${
            msg.kind === 'ok'
              ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200'
              : 'border-destructive/40 bg-destructive/10 text-destructive'
          }`}
        >
          {msg.text}
        </div>
      )}

      {tab === 'usuarios' && isAdmin && <UsersTab onFlash={flash} />}
      {tab === 'agentes' && <AgentsTab onFlash={flash} />}
      {tab === 'sistema' && <SystemTab onFlash={flash} />}
    </div>
  );
}
