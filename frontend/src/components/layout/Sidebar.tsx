/**
 * Barra lateral de navegacion del SOC, organizada por secciones
 * (Panel / Amenazas / Postura / Operacion) para escalar como un SOC moderno.
 */
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Gauge,
  Globe2,
  ShieldAlert,
  BellRing,
  FileBarChart,
  Users,
  HeartPulse,
  Bug,
  Crosshair,
  ClipboardCheck,
  FileSearch,
  Activity,
  Scale,
  ListFilter,
  Server,
  Briefcase,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useAuth } from '@/lib/auth';

type Role = 'admin' | 'analista' | 'lector';

interface Item {
  to: string;
  label: string;
  icon: typeof LayoutDashboard;
  roles?: Role[]; // si se define, solo esos roles ven el item
}

const sections: { title: string | null; items: Item[] }[] = [
  {
    title: null,
    items: [
      { to: '/resumen', label: 'Resumen Ejecutivo', icon: Gauge },
      { to: '/', label: 'Panel', icon: LayoutDashboard },
    ],
  },
  {
    title: 'Amenazas',
    items: [
      { to: '/alertas', label: 'Alertas', icon: ListFilter },
      { to: '/mapa', label: 'Mapa de ataques', icon: Globe2 },
      { to: '/mitre', label: 'MITRE ATT&CK', icon: Crosshair },
      { to: '/incidentes', label: 'Incidentes', icon: Briefcase },
      { to: '/respuesta', label: 'Respuesta', icon: ShieldAlert, roles: ['admin', 'analista'] },
    ],
  },
  {
    title: 'Postura / Endpoints',
    items: [
      { to: '/activos', label: 'Activos', icon: Server },
      { to: '/vulnerabilidades', label: 'Vulnerabilidades', icon: Bug },
      { to: '/sca', label: 'Config. Assessment', icon: ClipboardCheck },
      { to: '/fim', label: 'Integridad (FIM)', icon: FileSearch },
      { to: '/hygiene', label: 'IT Hygiene', icon: Activity },
    ],
  },
  {
    title: 'Cumplimiento',
    items: [{ to: '/cumplimiento', label: 'Cumplimiento', icon: Scale }],
  },
  {
    title: 'Operación',
    items: [
      { to: '/notificaciones', label: 'Notificaciones', icon: BellRing },
      { to: '/reportes', label: 'Reportes', icon: FileBarChart },
      { to: '/salud', label: 'Salud del SIEM', icon: HeartPulse },
      { to: '/gestion', label: 'Gestión', icon: Users, roles: ['admin'] },
    ],
  },
];

/** Navegacion reutilizable (desktop y drawer movil). */
export function SidebarNav({ onNavigate }: { onNavigate?: () => void }) {
  const { user } = useAuth();
  const role = (user?.role ?? 'lector') as Role;
  // Filtra items por rol y descarta secciones que queden vacias.
  const visibles = sections
    .map((s) => ({ ...s, items: s.items.filter((i) => !i.roles || i.roles.includes(role)) }))
    .filter((s) => s.items.length > 0);

  return (
    <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-4">
      {visibles.map((section, si) => (
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
              onClick={onNavigate}
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
  );
}

export function Sidebar() {
  return (
    <aside className="hidden md:flex w-60 shrink-0 flex-col border-r border-border/60 bg-card/40 backdrop-blur-xl">
      <div className="flex items-center gap-3 px-5 h-16 border-b border-border/60">
        <img
          src="/logo-emblem.png"
          alt="Parques Nacionales Naturales de Colombia"
          className="h-11 w-auto object-contain drop-shadow-sm"
        />
        <span className="text-base font-semibold tracking-wide">SOC</span>
      </div>
      <SidebarNav />
      <div className="px-5 py-4 border-t border-border/60 text-[11px] leading-relaxed text-muted-foreground/70">
        Parques Nacionales Naturales de Colombia
      </div>
    </aside>
  );
}
