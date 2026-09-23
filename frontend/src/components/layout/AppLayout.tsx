/** Layout principal: Sidebar (desktop) + drawer movil + Topbar + contenido. */
import { Suspense, useCallback, useEffect, useState, type ReactNode } from 'react';
import { Loader2, X } from 'lucide-react';
import { Sidebar, SidebarNav } from './Sidebar';
import { Topbar } from './Topbar';
import { CommandPalette } from './CommandPalette';
import { CopilotDock } from './CopilotDock';
import { fetchLicenseStatus, type LicenseStatus } from '@/lib/license';
import { LockScreen } from '@/components/LockScreen';

export function AppLayout({ children }: { children: ReactNode }) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [lic, setLic] = useState<LicenseStatus | null>(null);
  const [licLoading, setLicLoading] = useState(true);

  const refreshLic = useCallback(() => { void fetchLicenseStatus(true).then(setLic).catch(() => undefined); }, []);
  useEffect(() => {
    fetchLicenseStatus()
      .then(setLic)
      .catch(() => setLic({ state: 'none', message: 'No se pudo verificar la licencia.' }))
      .finally(() => setLicLoading(false));
    const h = () => refreshLic();
    window.addEventListener('hw-license-lock', h);
    return () => window.removeEventListener('hw-license-lock', h);
  }, [refreshLic]);

  if (licLoading) {
    return <div className="flex h-screen items-center justify-center text-muted-foreground"><Loader2 className="h-5 w-5 animate-spin" /></div>;
  }
  if (!lic || (lic.state !== 'active' && lic.state !== 'grace')) {
    return <LockScreen status={lic} onActivated={setLic} />;
  }

  return (
    <div className="flex h-screen flex-col overflow-hidden">
      <div className="flex flex-1 overflow-hidden">
        <Sidebar />

        {/* Drawer de navegacion en movil */}
        {mobileOpen && (
          <div className="fixed inset-0 z-50 md:hidden">
            <div className="absolute inset-0 bg-ink/40 backdrop-blur-sm" onClick={() => setMobileOpen(false)} />
            <aside className="absolute left-0 top-0 flex h-full w-64 flex-col border-r border-border bg-card shadow-2xl">
              <div className="flex h-16 items-center justify-between border-b border-border px-5">
                <div className="flex items-center gap-2.5">
                  <img
                    src="/logo-emblem.png"
                    alt="Click Solutions"
                    className="h-8 w-auto object-contain"
                  />
                  <span className="text-lg font-bold tracking-tight">HexWatch</span>
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
          {lic.state === 'grace' && (
            <div className="border-b border-red-500/40 bg-red-500/10 px-4 py-1.5 text-center text-xs font-medium text-red-700">
              ⚠ Licencia <b>VENCIDA</b>{lic.expiresAt ? ` el ${lic.expiresAt.slice(0, 10)}` : ''} · periodo de gracia: <b className="tabular-nums">{lic.graceDaysLeft} día(s)</b> antes del corte del servicio. Renueva YA en Operación → Licenciamiento.
            </div>
          )}
          {lic.state === 'active' && lic.renewalWarning && lic.daysLeft != null && (() => {
            const u = lic.urgency ?? 'info';
            const style = u === 'urgent'
              ? 'border-red-500/40 bg-red-500/10 text-red-700 font-medium'
              : u === 'warn'
                ? 'border-orange-500/40 bg-orange-500/10 text-orange-700'
                : 'border-amber-500/30 bg-amber-500/10 text-amber-700';
            return (
              <div className={`border-b px-4 py-1.5 text-center text-xs ${style}`}>
                {u === 'urgent' ? '⚠ ' : ''}Licencia por vencer: <b className="tabular-nums">{lic.daysLeft} día(s)</b> restantes{lic.expiresAt ? ` (vence ${lic.expiresAt.slice(0, 10)})` : ''}.
                {u === 'urgent' ? ' El servicio se bloqueará al vencer — ' : ' '}Renueva en Operación → Licenciamiento.
              </div>
            );
          })()}
          <main className="flex-1 overflow-y-auto p-4 md:p-6">
            <Suspense
              fallback={
                <div className="flex h-full items-center justify-center text-muted-foreground">
                  <Loader2 className="h-5 w-5 animate-spin" />
                </div>
              }
            >
              {children}
            </Suspense>
          </main>
        </div>
      </div>
      <CommandPalette />
      <CopilotDock />
    </div>
  );
}
