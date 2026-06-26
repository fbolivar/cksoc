/**
 * Barra lateral de navegacion del SOC.
 * Fase 1 solo habilita "Panel". El resto queda visible pero deshabilitado
 * para mostrar la arquitectura de fases siguientes.
 */
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Globe2,
  ShieldAlert,
  BellRing,
  FileBarChart,
  Users,
  Lock,
} from 'lucide-react';
import { cn } from '@/lib/utils';

const items = [
  { to: '/', label: 'Panel', icon: LayoutDashboard, enabled: true },
  { to: '/mapa', label: 'Mapa de ataques', icon: Globe2, enabled: true },
  { to: '/respuesta', label: 'Respuesta', icon: ShieldAlert, enabled: true },
  { to: '/notificaciones', label: 'Notificaciones', icon: BellRing, enabled: true },
  { to: '/reportes', label: 'Reportes', icon: FileBarChart, enabled: true },
  { to: '/gestion', label: 'Gestion', icon: Users, enabled: true },
];

export function Sidebar() {
  return (
    <aside className="hidden md:flex w-60 shrink-0 flex-col border-r border-border/60 bg-card/40 backdrop-blur-xl">
      <div className="flex items-center gap-2 px-5 h-16 border-b border-border/60">
        <span className="h-2.5 w-2.5 rounded-full bg-neon animate-pulse-soft shadow-glow" />
        <span className="text-sm font-semibold tracking-wide">SOC · PNNC</span>
      </div>
      <nav className="flex-1 px-3 py-4 space-y-1">
        {items.map(({ to, label, icon: Icon, enabled }) =>
          enabled ? (
            <NavLink
              key={to}
              to={to}
              end
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-3 rounded-md px-3 py-2.5 text-sm transition-colors',
                  isActive
                    ? 'bg-primary/15 text-primary-foreground border border-primary/30'
                    : 'text-muted-foreground hover:bg-secondary hover:text-foreground'
                )
              }
            >
              <Icon className="h-4 w-4" />
              {label}
            </NavLink>
          ) : (
            <div
              key={to}
              className="flex items-center justify-between gap-3 rounded-md px-3 py-2.5 text-sm text-muted-foreground/40 cursor-not-allowed select-none"
              title="Disponible en una fase siguiente"
            >
              <span className="flex items-center gap-3">
                <Icon className="h-4 w-4" />
                {label}
              </span>
              <Lock className="h-3 w-3" />
            </div>
          )
        )}
      </nav>
      <div className="px-5 py-4 border-t border-border/60 text-[11px] leading-relaxed text-muted-foreground/70">
        Parques Nacionales Naturales de Colombia
      </div>
    </aside>
  );
}
