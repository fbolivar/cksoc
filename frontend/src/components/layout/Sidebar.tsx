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
  Crosshair,
  ClipboardCheck,
  FileSearch,
  Activity,
  Scale,
  ListFilter,
  Server,
  Briefcase,
  DatabaseBackup,
  ScrollText,
  Radar,
  LineChart,
  Zap,
  ShieldCheck,
  SlidersHorizontal,
  Rss,
  GitMerge,
  Workflow,
  Grid3x3,
  UserSearch,
  Sparkles,
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
    title: 'Vista general',
    items: [
      { to: '/', label: 'Command Center', icon: LayoutDashboard },
      { to: '/resumen', label: 'Resumen Ejecutivo', icon: ShieldCheck },
      { to: '/copiloto', label: 'Copiloto IA', icon: Sparkles, roles: ['admin', 'analista'] },
      { to: '/metricas', label: 'Métricas SOC', icon: LineChart, roles: ['admin', 'analista'] },
    ],
  },
  {
    title: 'Detectar',
    items: [
      { to: '/alertas', label: 'Alertas', icon: ListFilter },
      { to: '/deteccion', label: 'Detecciones', icon: SlidersHorizontal, roles: ['admin', 'analista'] },
      { to: '/mitre', label: 'MITRE ATT&CK', icon: Crosshair },
      { to: '/cobertura-mitre', label: 'Cobertura MITRE', icon: Grid3x3, roles: ['admin', 'analista'] },
      { to: '/comportamiento', label: 'Comportamiento (UEBA)', icon: UserSearch, roles: ['admin', 'analista'] },
      { to: '/correlacion', label: 'Correlación', icon: GitMerge, roles: ['admin', 'analista'] },
      { to: '/mapa', label: 'Mapa de ataques', icon: Globe2 },
    ],
  },
  {
    title: 'Investigar',
    items: [
      { to: '/hunting', label: 'Threat Hunting', icon: Radar, roles: ['admin', 'analista'] },
      { to: '/threat-intel', label: 'Threat Intelligence', icon: Rss, roles: ['admin', 'analista'] },
      { to: '/velociraptor', label: 'Velociraptor (DFIR)', icon: Crosshair, roles: ['admin', 'analista'] },
    ],
  },
  {
    title: 'Responder',
    items: [
      { to: '/incidentes', label: 'Incidentes', icon: Briefcase },
      { to: '/respuesta', label: 'Respuesta · FortiGate', icon: ShieldAlert, roles: ['admin', 'analista'] },
      { to: '/soar', label: 'Automatización (SOAR)', icon: Workflow, roles: ['admin', 'analista'] },
      { to: '/playbooks', label: 'Playbooks', icon: Zap, roles: ['admin', 'analista'] },
    ],
  },
  {
    title: 'Postura',
    items: [
      { to: '/activos', label: 'Activos', icon: Server },
      { to: '/vulnerabilidades', label: 'Vulnerabilidades', icon: Bug },
      { to: '/sca', label: 'Config. Assessment', icon: ClipboardCheck },
      { to: '/fim', label: 'Integridad (FIM)', icon: FileSearch },
      { to: '/hygiene', label: 'IT Hygiene', icon: Activity },
      { to: '/cumplimiento', label: 'Cumplimiento', icon: Scale },
    ],
  },
  {
    title: 'Reportes',
    items: [{ to: '/reportes', label: 'Reportes', icon: FileBarChart }],
  },
  {
    title: 'Operación',
    items: [
      { to: '/notificaciones', label: 'Notificaciones', icon: BellRing },
      { to: '/salud', label: 'Salud del SIEM', icon: HeartPulse },
      { to: '/respaldos', label: 'Respaldos', icon: DatabaseBackup, roles: ['admin'] },
      { to: '/auditoria', label: 'Auditoría', icon: ScrollText, roles: ['admin'] },
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
    <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-5">
      {visibles.map((section, si) => (
        <div key={si} className="space-y-1">
          {section.title && (
            <p className="hw-mono flex items-center gap-2 px-3 pb-1.5 pt-1 text-[9.5px] font-bold uppercase tracking-[0.16em] text-primary/80">
              {section.title}
              <span className="h-px flex-1 bg-border" />
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
                  'group flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm transition-colors',
                  isActive
                    ? 'bg-secondary font-semibold text-foreground'
                    : 'text-muted-foreground hover:bg-secondary/60 hover:text-foreground'
                )
              }
            >
              {({ isActive }) => (
                <>
                  <Icon className={cn('h-[18px] w-[18px] shrink-0', isActive ? 'text-primary' : 'text-muted-foreground group-hover:text-foreground')} />
                  <span className="truncate">{label}</span>
                </>
              )}
            </NavLink>
          ))}
        </div>
      ))}
    </nav>
  );
}

export function Sidebar() {
  return (
    <aside className="hidden md:flex w-64 shrink-0 flex-col border-r border-border bg-card">
      <div className="flex items-center gap-2.5 px-5 h-16 border-b border-border">
        <img
          src="/logo-emblem.png"
          alt="HexWatch"
          className="h-8 w-auto object-contain"
        />
        <span className="text-lg font-bold tracking-tight">HexWatch</span>
      </div>
      <SidebarNav />
      <div className="px-5 py-4 border-t border-border text-[11px] leading-relaxed text-muted-foreground/70">
        HexWatch · BC Security
      </div>
    </aside>
  );
}
