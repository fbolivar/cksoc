/** Licenciamiento (Operación): estado de la licencia y carga del código. */
import { useEffect, useState } from 'react';
import { AxiosError } from 'axios';
import { KeyRound, ShieldCheck, ShieldAlert, RefreshCw, Loader2 } from 'lucide-react';
import { fetchLicenseStatus, activateLicense, type LicenseStatus } from '@/lib/license';
import { useAuth } from '@/lib/auth';
import { Card, CardContent } from '@/components/ui/card';

export default function License() {
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';
  const [st, setSt] = useState<LicenseStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  function load() { setLoading(true); fetchLicenseStatus(true).then(setSt).catch(() => undefined).finally(() => setLoading(false)); }
  useEffect(() => { load(); }, []);

  async function activar() {
    if (!code.trim()) return;
    setBusy(true); setMsg(null);
    try {
      const s = await activateLicense(code.trim());
      setSt(s);
      setMsg(s.state === 'active' ? 'Licencia activada correctamente.' : s.message);
      if (s.state === 'active') setCode('');
    } catch (e) {
      setMsg((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo activar la licencia');
    } finally { setBusy(false); }
  }

  const active = st?.state === 'active';
  const color = active ? 'var(--success)' : 'var(--destructive)';

  return (
    <div className="mx-auto max-w-3xl space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="hw-mono flex items-center gap-2 text-2xl font-bold tracking-tight"><KeyRound className="h-6 w-6 text-primary" /> Licenciamiento</h1>
          <p className="text-sm text-muted-foreground">Estado de la licencia y carga del código de activación</p>
        </div>
        <button onClick={load} className="rounded-md border border-input p-2 text-muted-foreground hover:text-foreground"><RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} /></button>
      </div>

      <Card><CardContent className="p-5">
        {loading && !st ? (
          <p className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Verificando licencia…</p>
        ) : (
          <div className="flex items-start gap-4">
            <div className="grid h-12 w-12 shrink-0 place-items-center rounded-xl" style={{ background: `hsl(${color} / .12)` }}>
              {active ? <ShieldCheck className="h-6 w-6" style={{ color: `hsl(${color})` }} /> : <ShieldAlert className="h-6 w-6" style={{ color: `hsl(${color})` }} />}
            </div>
            <div className="flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="rounded px-2 py-0.5 text-[11px] font-bold uppercase" style={{ color: `hsl(${color})`, background: `hsl(${color} / .12)` }}>{st?.state ?? '—'}</span>
                <span className="text-sm font-semibold">{st?.message}</span>
              </div>
              <div className="mt-3 grid grid-cols-2 gap-3 text-sm sm:grid-cols-3">
                <div><p className="text-[11px] text-muted-foreground">Cliente</p><p className="font-medium">{st?.customer ?? '—'}</p></div>
                <div><p className="text-[11px] text-muted-foreground">Vence</p><p className="font-medium">{st?.expiresAt ? st.expiresAt.slice(0, 10) : '—'}</p></div>
                <div><p className="text-[11px] text-muted-foreground">Días restantes</p><p className="font-medium tabular-nums">{st?.daysLeft ?? '—'}</p></div>
              </div>
              {st?.clockWarning && <p className="mt-2 text-xs text-amber-700">Aviso: el reloj del servidor parece haberse atrasado respecto al último registro.</p>}
            </div>
          </div>
        )}
      </CardContent></Card>

      {isAdmin ? (
        <Card><CardContent className="p-5">
          <p className="mb-2 text-sm font-semibold">Cargar / renovar código</p>
          <textarea value={code} onChange={(e) => setCode(e.target.value)} rows={4} placeholder="HEXW1...."
            className="mb-2 w-full resize-none rounded-md border border-input bg-background p-2 font-mono text-xs outline-none focus:border-primary" />
          {msg && <p className="mb-2 text-xs" style={{ color: 'hsl(var(--primary))' }}>{msg}</p>}
          <button onClick={activar} disabled={busy || !code.trim()}
            className="flex items-center gap-2 rounded-md px-4 py-2 text-sm font-semibold text-white disabled:opacity-50" style={{ background: 'hsl(var(--primary))' }}>
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <KeyRound className="h-4 w-4" />} Activar
          </button>
          <p className="mt-3 text-[11px] text-muted-foreground/70">El código lo emite el proveedor con la duración acordada. Sin licencia vigente, la aplicación se bloquea por completo.</p>
        </CardContent></Card>
      ) : (
        <Card><CardContent className="p-5 text-sm text-muted-foreground">Solo un administrador puede cargar el código de licencia.</CardContent></Card>
      )}
    </div>
  );
}
