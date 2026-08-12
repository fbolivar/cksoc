/**
 * Barra superior HexWatch: fondo claro, título del módulo, cambio de tema
 * y menú de usuario con cierre de sesión.
 */
import { LogOut, ShieldCheck, Menu } from 'lucide-react';
import { Link } from 'react-router-dom';
import { useAuth } from '@/lib/auth';
import { Button } from '@/components/ui/button';
import { ThemeToggle } from './ThemeToggle';
import { NotificationBell } from './NotificationBell';

const roleLabels: Record<string, string> = {
  admin: 'Administrador',
  analista: 'Analista',
  lector: 'Lector',
};

export function Topbar({ onMenuClick }: { onMenuClick?: () => void }) {
  const { user, logout } = useAuth();

  return (
    <header className="relative z-40 h-16 shrink-0 flex items-center justify-between gap-4 px-5 bg-card/80 backdrop-blur-xl border-b border-border">
      <div className="flex items-center gap-3 min-w-0">
        <button onClick={onMenuClick} className="md:hidden text-muted-foreground hover:text-foreground" aria-label="Abrir menú">
          <Menu className="h-6 w-6" />
        </button>
        <div className="hidden sm:flex items-center gap-2.5 min-w-0">
          <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-accent text-primary">
            <ShieldCheck className="h-5 w-5" />
          </span>
          <div className="leading-tight">
            <p className="text-sm font-semibold text-foreground">Centro de Operaciones de Seguridad</p>
            <p className="text-[11px] text-muted-foreground">Monitoreo Wazuh · Tiempo real</p>
          </div>
        </div>
      </div>

      <div className="flex items-center gap-2.5">
        <NotificationBell />
        <ThemeToggle />
        {user && (
          <Link to="/cuenta" className="flex items-center gap-2.5 rounded-full border border-border bg-card px-2 py-1 pr-3 hover:bg-secondary transition-colors" title="Mi cuenta y seguridad">
            <span className="flex h-8 w-8 items-center justify-center rounded-full bg-ink text-background text-xs font-semibold">
              {(user.fullName || user.email).slice(0, 1).toUpperCase()}
            </span>
            <span className="text-right leading-tight hidden sm:block">
              <span className="block text-sm font-medium text-foreground">{user.fullName}</span>
              <span className="block text-[11px] text-primary">{roleLabels[user.role] ?? user.role}</span>
            </span>
          </Link>
        )}
        <Button variant="outline" size="sm" onClick={logout}>
          <LogOut className="h-4 w-4" />
          <span className="hidden sm:inline">Salir</span>
        </Button>
      </div>
    </header>
  );
}
