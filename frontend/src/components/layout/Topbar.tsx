/**
 * Barra superior HexWatch: fondo claro, título del módulo, cambio de tema
 * y menú de usuario con cierre de sesión.
 */
import { LogOut, Menu, Search } from 'lucide-react';
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
        <span className="hw-mono hidden text-sm font-bold tracking-wide sm:block">HEX<span className="text-primary" style={{ textShadow: '0 0 12px hsl(var(--primary)/.5)' }}>WATCH</span></span>
        <button
          onClick={() => window.dispatchEvent(new Event('hw-open-palette'))}
          className="hw-clip hw-mono flex min-w-[180px] items-center gap-2 border border-border bg-secondary/50 px-3 py-2 text-[12.5px] text-muted-foreground transition-colors hover:border-primary/50 hover:text-foreground sm:min-w-[240px]"
          title="Buscar (Ctrl+K)"
        >
          <Search className="h-3.5 w-3.5" />
          buscar // ejecutar
          <span className="ml-auto bg-foreground/10 px-1.5 py-0.5 text-[10px]">CTRL K</span>
        </button>
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
