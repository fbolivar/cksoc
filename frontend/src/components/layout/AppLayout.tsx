/** Layout principal: Sidebar (desktop) + drawer movil + Topbar + contenido. */
import { useState, type ReactNode } from 'react';
import { X } from 'lucide-react';
import { Sidebar, SidebarNav } from './Sidebar';
import { Topbar } from './Topbar';

export function AppLayout({ children }: { children: ReactNode }) {
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <div className="flex h-screen flex-col overflow-hidden">
      {/* Franja tricolor gov.co - identidad de Gobierno de Colombia */}
      <div className="gov-strip shrink-0" />
      <div className="flex flex-1 overflow-hidden">
      <Sidebar />

      {/* Drawer de navegacion en movil */}
      {mobileOpen && (
        <div className="fixed inset-0 z-50 md:hidden">
          <div className="absolute inset-0 bg-black/60" onClick={() => setMobileOpen(false)} />
          <aside className="absolute left-0 top-0 flex h-full w-64 flex-col border-r border-border/60 bg-card shadow-2xl">
            <div className="flex h-16 items-center justify-between border-b border-border/60 px-5">
              <div className="flex items-center gap-3">
                <img
                  src="/logo-emblem.png"
                  alt="Parques Nacionales Naturales de Colombia"
                  className="h-10 w-auto object-contain drop-shadow-sm"
                />
                <span className="text-base font-semibold tracking-wide">SOC</span>
              </div>
              <button onClick={() => setMobileOpen(false)} className="text-muted-foreground hover:text-foreground" aria-label="Cerrar menú">
                <X className="h-5 w-5" />
              </button>
            </div>
            <SidebarNav onNavigate={() => setMobileOpen(false)} />
          </aside>
        </div>
      )}

      <div className="flex flex-1 flex-col overflow-hidden">
        <Topbar onMenuClick={() => setMobileOpen(true)} />
        <main className="flex-1 overflow-y-auto p-4 md:p-6">{children}</main>
      </div>
      </div>
    </div>
  );
}
