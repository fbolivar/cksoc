/**
 * Barra superior con identidad Parques Nacionales (verde institucional),
 * titulo del modulo, cambio de tema y menu de usuario con cierre de sesion.
 * El emblema PNNC vive en el encabezado del sidebar, no aqui.
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
    <header className="relative z-40 h-16 shrink-0 flex items-center justify-between gap-4 px-5 bg-gradient-to-r from-[hsl(146_60%_14%)] via-[hsl(156_28%_9%)] to-[hsl(197_45%_11%)] backdrop-blur-xl border-b border-primary/25">
      <div className="flex items-center gap-3 min-w-0">
        <button onClick={onMenuClick} className="md:hidden text-white/80 hover:text-white" aria-label="Abrir menú">
          <Menu className="h-6 w-6" />
        </button>
        <div className="hidden sm:flex items-center gap-2 min-w-0">
          <ShieldCheck className="h-5 w-5 shrink-0 text-neon" />
          <div className="leading-tight">
            <p className="text-sm font-semibold text-white">Centro de Operaciones de Seguridad</p>
            <p className="text-[11px] text-white/60">Monitoreo Wazuh · Tiempo real</p>
          </div>
        </div>
      </div>

      <div className="flex items-center gap-3">
        <NotificationBell />
        <ThemeToggle />
        {user && (
          <Link to="/cuenta" className="text-right leading-tight hidden sm:block rounded px-2 py-1 hover:bg-white/10 transition-colors" title="Mi cuenta y seguridad">
            <p className="text-sm font-medium text-white">{user.fullName}</p>
            <p className="text-[11px] text-neon">{roleLabels[user.role] ?? user.role}</p>
          </Link>
        )}
        <Button variant="outline" size="sm" onClick={logout} className="border-white/20 text-white hover:bg-white/10">
          <LogOut className="h-4 w-4" />
          <span className="hidden sm:inline">Salir</span>
        </Button>
      </div>
    </header>
  );
}
