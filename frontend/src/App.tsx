/**
 * Rutas de la aplicacion.
 * - /login  : publico
 * - /        : dashboard (protegido)
 * Las rutas protegidas requieren sesion; si no hay, redirigen a /login.
 */
import { lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { useAuth } from '@/lib/auth';
import { AppLayout } from '@/components/layout/AppLayout';
import Login from '@/pages/Login'; // eager: primera carga (publica)

// Carga diferida por ruta: cada pagina es su propio chunk, se descarga solo al
// visitarla. Reduce el bundle inicial (antes ~1 MB en un solo archivo).
const CommandCenter = lazy(() => import('@/pages/CommandCenter'));
const ExecutiveSummary = lazy(() => import('@/pages/ExecutiveSummary'));
const AttackMap = lazy(() => import('@/pages/AttackMap'));
const Alerts = lazy(() => import('@/pages/Alerts'));
const Incidents = lazy(() => import('@/pages/Incidents'));
const Mitre = lazy(() => import('@/pages/Mitre'));
const Response = lazy(() => import('@/pages/Response'));
const Notifications = lazy(() => import('@/pages/Notifications'));
const Reports = lazy(() => import('@/pages/Reports'));
const SiemHealth = lazy(() => import('@/pages/SiemHealth'));
const Vulnerabilities = lazy(() => import('@/pages/Vulnerabilities'));
const Assets = lazy(() => import('@/pages/Assets'));
const Sca = lazy(() => import('@/pages/Sca'));
const Fim = lazy(() => import('@/pages/Fim'));
const Hygiene = lazy(() => import('@/pages/Hygiene'));
const Compliance = lazy(() => import('@/pages/Compliance'));
const Management = lazy(() => import('@/pages/Management'));
const Account = lazy(() => import('@/pages/Account'));
const Backups = lazy(() => import('@/pages/Backups'));
const Audit = lazy(() => import('@/pages/Audit'));
const SocMetrics = lazy(() => import('@/pages/SocMetrics'));
const Hunt = lazy(() => import('@/pages/Hunt'));
const Velociraptor = lazy(() => import('@/pages/Velociraptor'));
const Detection = lazy(() => import('@/pages/Detection'));
const ThreatIntel = lazy(() => import('@/pages/ThreatIntel'));
const CorrelationPage = lazy(() => import('@/pages/Correlation'));
const Soar = lazy(() => import('@/pages/Soar'));
const Ueba = lazy(() => import('@/pages/Ueba'));
const Copilot = lazy(() => import('@/pages/Copilot'));

function Protected({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center text-muted-foreground">
        Cargando…
      </div>
    );
  }
  return user ? <>{children}</> : <Navigate to="/login" replace />;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/"
        element={
          <Protected>
            <AppLayout>
              <CommandCenter />
            </AppLayout>
          </Protected>
        }
      />
      <Route
        path="/resumen"
        element={
          <Protected>
            <AppLayout>
              <ExecutiveSummary />
            </AppLayout>
          </Protected>
        }
      />
      <Route
        path="/alertas"
        element={
          <Protected>
            <AppLayout>
              <Alerts />
            </AppLayout>
          </Protected>
        }
      />
      <Route
        path="/incidentes"
        element={
          <Protected>
            <AppLayout>
              <Incidents />
            </AppLayout>
          </Protected>
        }
      />
      <Route
        path="/mapa"
        element={
          <Protected>
            <AppLayout>
              <AttackMap />
            </AppLayout>
          </Protected>
        }
      />
      <Route
        path="/mitre"
        element={
          <Protected>
            <AppLayout>
              <Mitre />
            </AppLayout>
          </Protected>
        }
      />
      <Route
        path="/respuesta"
        element={
          <Protected>
            <AppLayout>
              <Response />
            </AppLayout>
          </Protected>
        }
      />
      <Route
        path="/notificaciones"
        element={
          <Protected>
            <AppLayout>
              <Notifications />
            </AppLayout>
          </Protected>
        }
      />
      <Route
        path="/reportes"
        element={
          <Protected>
            <AppLayout>
              <Reports />
            </AppLayout>
          </Protected>
        }
      />
      <Route
        path="/activos"
        element={
          <Protected>
            <AppLayout>
              <Assets />
            </AppLayout>
          </Protected>
        }
      />
      <Route
        path="/vulnerabilidades"
        element={
          <Protected>
            <AppLayout>
              <Vulnerabilities />
            </AppLayout>
          </Protected>
        }
      />
      <Route
        path="/sca"
        element={
          <Protected>
            <AppLayout>
              <Sca />
            </AppLayout>
          </Protected>
        }
      />
      <Route
        path="/fim"
        element={
          <Protected>
            <AppLayout>
              <Fim />
            </AppLayout>
          </Protected>
        }
      />
      <Route
        path="/hygiene"
        element={
          <Protected>
            <AppLayout>
              <Hygiene />
            </AppLayout>
          </Protected>
        }
      />
      <Route
        path="/salud"
        element={
          <Protected>
            <AppLayout>
              <SiemHealth />
            </AppLayout>
          </Protected>
        }
      />
      <Route
        path="/cumplimiento"
        element={
          <Protected>
            <AppLayout>
              <Compliance />
            </AppLayout>
          </Protected>
        }
      />
      <Route
        path="/cuenta"
        element={
          <Protected>
            <AppLayout>
              <Account />
            </AppLayout>
          </Protected>
        }
      />
      <Route
        path="/gestion"
        element={
          <Protected>
            <AppLayout>
              <Management />
            </AppLayout>
          </Protected>
        }
      />
      <Route
        path="/respaldos"
        element={
          <Protected>
            <AppLayout>
              <Backups />
            </AppLayout>
          </Protected>
        }
      />
      <Route
        path="/auditoria"
        element={
          <Protected>
            <AppLayout>
              <Audit />
            </AppLayout>
          </Protected>
        }
      />
      <Route
        path="/metricas"
        element={
          <Protected>
            <AppLayout>
              <SocMetrics />
            </AppLayout>
          </Protected>
        }
      />
      <Route
        path="/hunting"
        element={
          <Protected>
            <AppLayout>
              <Hunt />
            </AppLayout>
          </Protected>
        }
      />
      <Route
        path="/velociraptor"
        element={
          <Protected>
            <AppLayout>
              <Velociraptor />
            </AppLayout>
          </Protected>
        }
      />
      <Route
        path="/deteccion"
        element={
          <Protected>
            <AppLayout>
              <Detection />
            </AppLayout>
          </Protected>
        }
      />
      <Route
        path="/threat-intel"
        element={
          <Protected>
            <AppLayout>
              <ThreatIntel />
            </AppLayout>
          </Protected>
        }
      />
      <Route
        path="/correlacion"
        element={
          <Protected>
            <AppLayout>
              <CorrelationPage />
            </AppLayout>
          </Protected>
        }
      />
      <Route
        path="/soar"
        element={
          <Protected>
            <AppLayout>
              <Soar />
            </AppLayout>
          </Protected>
        }
      />
      <Route
        path="/comportamiento"
        element={
          <Protected>
            <AppLayout>
              <Ueba />
            </AppLayout>
          </Protected>
        }
      />
      <Route
        path="/copiloto"
        element={
          <Protected>
            <AppLayout>
              <Copilot />
            </AppLayout>
          </Protected>
        }
      />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
