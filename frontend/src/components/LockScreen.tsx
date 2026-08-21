/** Pantalla de bloqueo cuando no hay licencia válida/vigente. */
import { useState } from 'react';
import { AxiosError } from 'axios';
import { ShieldAlert, Loader2, KeyRound, LogOut } from 'lucide-react';
import { useAuth } from '@/lib/auth';
import { activateLicense, type LicenseStatus } from '@/lib/license';

const TITLE: Record<string, string> = {
  none: 'Se requiere activación',
  expired: 'Licencia vencida',
  invalid: 'Licencia inválida',
  active: '',
};

export function LockScreen({ status, onActivated }: { status: LicenseStatus | null; onActivated: (s: LicenseStatus) => void }) {
  const { user, logout } = useAuth();
  const isAdmin = user?.role === 'admin';
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function submit() {
    if (!code.trim()) return;
    setBusy(true); setErr(null);
    try {
      const s = await activateLicense(code.trim());
      if (s.state === 'active') onActivated(s);
      else setErr(s.message);
    } catch (e) {
      setErr((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo activar la licencia');
    } finally { setBusy(false); }
  }

  return (
    <div className="flex h-screen items-center justify-center bg-background p-4">
      <div className="w-full max-w-md rounded-2xl border border-border bg-card p-8 shadow-2xl">
        <div className="mb-4 flex items-center gap-3">
          <div className="grid h-11 w-11 place-items-center rounded-xl" style={{ background: 'hsl(var(--destructive) / .12)' }}>
            <ShieldAlert className="h-6 w-6" style={{ color: 'hsl(var(--destructive))' }} />
          </div>
          <div>
            <p className="text-lg font-bold">HexWatch bloqueado</p>
            <p className="text-xs text-muted-foreground">{TITLE[status?.state ?? 'none'] || 'Se requiere licencia'}</p>
          </div>
        </div>
        <p className="mb-4 text-sm text-muted-foreground">
          {status?.message ?? 'La aplicación requiere una licencia válida para funcionar.'}
          {status?.customer ? ` · ${status.customer}` : ''}
        </p>
        {isAdmin ? (
          <>
            <label className="mb-1 block text-xs font-medium text-muted-foreground">Código de activación</label>
            <textarea value={code} onChange={(e) => setCode(e.target.value)} rows={4} placeholder="HEXW1...."
              className="mb-2 w-full resize-none rounded-md border border-input bg-background p-2 font-mono text-xs outline-none focus:border-primary" />
            {err && <p className="mb-2 text-xs text-rose-600">{err}</p>}
            <button onClick={submit} disabled={busy || !code.trim()}
              className="flex w-full items-center justify-center gap-2 rounded-md py-2 text-sm font-semibold text-white disabled:opacity-50" style={{ background: 'hsl(var(--primary))' }}>
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <KeyRound className="h-4 w-4" />} Activar
            </button>
          </>
        ) : (
          <p className="rounded-md border border-border bg-secondary/40 p-3 text-xs text-muted-foreground">
            Contacta al administrador para activar la licencia de HexWatch.
          </p>
        )}
        <button onClick={logout} className="mt-4 flex w-full items-center justify-center gap-1.5 text-xs text-muted-foreground hover:text-foreground">
          <LogOut className="h-3.5 w-3.5" /> Cerrar sesión
        </button>
      </div>
    </div>
  );
}
