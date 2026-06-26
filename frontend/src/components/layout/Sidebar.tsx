/**
 * Barra lateral de navegacion del SOC, organizada por secciones
 * (Panel / Amenazas / Postura / Operacion) para escalar como un SOC moderno.
 */
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Globe2,
  ShieldAlert,
  BellRing,
  FileBarChart,
  Users,
  HeartPulse,
  Bug,
} from 'lucide-react';
import { cn } from '@/lib/utils';

interface Item {
  to: string;
  label: string;
  icon: typeof LayoutDashboard;
}

const sections: { title: string | null; items: Item[] }[] = [
  { title: null, items: [{ to: '/', label: 'Panel', icon: LayoutDashboard }] },
  {
    title: 'Amenazas',
    items: [
      { to: '/mapa', label: 'Mapa de ataques', icon: Globe2 },
      { to: '/respuesta', label: 'Respuesta', icon: ShieldAlert },
    ],
  },
  {
    title: 'Postura / Endpoints',
    items: [{ to: '/vulnerabilidades', label: 'Vulnerabilidades', icon: Bug }],
  },
  {
    title: 'Operación',
    items: [
      { to: '/notificaciones', label: 'Notificaciones', icon: BellRing },
      { to: '/reportes', label: 'Reportes', icon: FileBarChart },
      { to: '/salud', label: 'Salud del SIEM', icon: HeartPulse },
      { to: '/gestion', label: 'Gestión', icon: Users },
    ],
  },
];

export function Sidebar() {
  return (
    <aside className="hidden md:flex w-60 shrink-0 flex-col border-r border-border/60 bg-card/40 backdrop-blur-xl">
      <div className="flex items-center gap-2 px-5 h-16 border-b border-border/60">
        <span className="h-2.5 w-2.5 rounded-full bg-neon animate-pulse-soft shadow-glow" />
        <span className="text-sm font-semibold tracking-wide">SOC · PNNC</span>
      </div>
      <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-4">
        {sections.map((section, si) => (
          <div key={si} className="space-y-1">
            {section.title && (
              <p className="px-3 pb-1 pt-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/50">
                {section.title}
              </p>
            )}
            {section.items.map(({ to, label, icon: Icon }) => (
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
            ))}
          </div>
        ))}
      </nav>
      <div className="px-5 py-4 border-t border-border/60 text-[11px] leading-relaxed text-muted-foreground/70">
        Parques Nacionales Naturales de Colombia
      </div>
    </aside>
  );
}
