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
import AttackMap from '@/pages/AttackMap';
import Response from '@/pages/Response';
import Notifications from '@/pages/Notifications';
import Reports from '@/pages/Reports';
import SiemHealth from '@/pages/SiemHealth';
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
