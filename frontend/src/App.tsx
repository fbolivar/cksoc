/**
 * Rutas de la aplicacion.
 * - /login  : publico
 * - /        : dashboard (protegido)
 * Las rutas protegidas requieren sesion; si no hay, redirigen a /login.
 */
import { Navigate, Route, Routes } from 'react-router-dom';
import { useAuth } from '@/lib/auth';
import { AppLayout } from '@/components/layout/AppLayout';
import Login from '@/pages/Login';
import Dashboard from '@/pages/Dashboard';
import Overview from '@/pages/Overview';
import AttackMap from '@/pages/AttackMap';
import Alerts from '@/pages/Alerts';
import Incidents from '@/pages/Incidents';
import Mitre from '@/pages/Mitre';
import Response from '@/pages/Response';
import Notifications from '@/pages/Notifications';
import Reports from '@/pages/Reports';
import SiemHealth from '@/pages/SiemHealth';
import Vulnerabilities from '@/pages/Vulnerabilities';
import Assets from '@/pages/Assets';
import Sca from '@/pages/Sca';
import Fim from '@/pages/Fim';
import Hygiene from '@/pages/Hygiene';
import Compliance from '@/pages/Compliance';
import Management from '@/pages/Management';

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
              <Dashboard />
            </AppLayout>
          </Protected>
        }
      />
      <Route
        path="/resumen"
        element={
          <Protected>
            <AppLayout>
              <Overview />
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
        path="/gestion"
        element={
          <Protected>
            <AppLayout>
              <Management />
            </AppLayout>
          </Protected>
        }
      />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
