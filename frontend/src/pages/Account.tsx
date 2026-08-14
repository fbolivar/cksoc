/**
 * Mi cuenta / Seguridad: gestion del 2FA (TOTP) y cambio de contrasena propia.
 */
import { useEffect, useState } from 'react';
import { AxiosError } from 'axios';
import { ShieldCheck, ShieldOff, KeyRound, Loader2, Check, Copy, Lock, UserCircle, LogOut } from 'lucide-react';
import { useAuth } from '@/lib/auth';
import { twofaApi, sessionApi } from '@/lib/account';
import { usersApi } from '@/lib/users';
import { tokenStorage } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

const roleLabels: Record<string, string> = { admin: 'Administrador', analista: 'Analista', lector: 'Lector' };
const errMsg = (e: unknown, d: string) => (e as AxiosError<{ error?: string }>).response?.data?.error ?? d;

export default function Account() {
  const { user } = useAuth();
  return (
    <div className="mx-auto max-w-3xl space-y-5">
      <div>
        <h1 className="flex items-center gap-2 hw-mono text-2xl font-bold tracking-tight">
          <UserCircle className="h-6 w-6 text-neon" /> Mi cuenta
        </h1>
        <p className="text-sm text-muted-foreground">
          {user?.fullName} · {user?.email} · {roleLabels[user?.role ?? ''] ?? user?.role}
        </p>
      </div>
      <TwoFactorCard />
      <PasswordCard />
      <SessionsCard />
    </div>
  );
}

function SessionsCard() {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  async function logoutAll() {
    setBusy(true); setMsg(null);
    try {
      const { token } = await sessionApi.logoutAll();
      tokenStorage.set(token); // esta sesion sigue viva con el token nuevo
      setMsg('Se cerraron las demás sesiones. Este dispositivo sigue conectado.');
    } catch (e) {
      setMsg(errMsg(e, 'No se pudo cerrar las sesiones'));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><LogOut className="h-4 w-4 text-neon" /> Sesiones</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-sm text-muted-foreground">
          Si sospechas que tu cuenta fue comprometida, cierra la sesión en todos los demás dispositivos.
          Los tokens activos dejarán de funcionar de inmediato.
        </p>
        {msg && <p className="text-sm text-neon">{msg}</p>}
        <Button variant="outline" onClick={logoutAll} disabled={busy}>
          {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <LogOut className="h-4 w-4" />} Cerrar sesión en todos los dispositivos
        </Button>
      </CardContent>
    </Card>
  );
}

function TwoFactorCard() {
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [mode, setMode] = useState<'idle' | 'setup' | 'backup' | 'disable'>('idle');
  const [qr, setQr] = useState<string>('');
  const [secret, setSecret] = useState<string>('');
  const [code, setCode] = useState('');
  const [password, setPassword] = useState('');
  const [backup, setBackup] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const reload = () => twofaApi.status().then((s) => setEnabled(s.enabled)).catch(() => setEnabled(false));
  useEffect(() => { reload(); }, []);

  function reset() {
    setMode('idle'); setQr(''); setSecret(''); setCode(''); setPassword(''); setError(null);
  }

  async function startSetup() {
    setBusy(true); setError(null);
    try {
      const s = await twofaApi.setup();
      setQr(s.qr); setSecret(s.secret); setMode('setup');
    } catch (e) { setError(errMsg(e, 'No se pudo iniciar el 2FA')); }
    finally { setBusy(false); }
  }

  async function confirmEnable() {
    setBusy(true); setError(null);
    try {
      const r = await twofaApi.enable(code.trim());
      setBackup(r.backupCodes); setMode('backup'); setCode('');
    } catch (e) { setError(errMsg(e, 'Código inválido')); }
    finally { setBusy(false); }
  }

  async function confirmDisable() {
    setBusy(true); setError(null);
    try {
      await twofaApi.disable(password, code.trim());
      reset(); await reload();
    } catch (e) { setError(errMsg(e, 'No se pudo desactivar')); }
    finally { setBusy(false); }
  }

  function copyBackup() {
    navigator.clipboard.writeText(backup.join('\n')).then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000); });
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <KeyRound className="h-4 w-4 text-neon" /> Autenticación en dos pasos (2FA)
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {enabled === null ? (
          <p className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Cargando…</p>
        ) : (
          <>
            <div className="flex items-center gap-2 text-sm">
              {enabled ? (
                <><span className="inline-flex items-center gap-1 rounded bg-neon/15 px-2 py-0.5 text-xs font-semibold text-neon"><ShieldCheck className="h-3.5 w-3.5" /> Activado</span>
                  <span className="text-muted-foreground">Tu cuenta pide un código adicional al iniciar sesión.</span></>
              ) : (
                <><span className="inline-flex items-center gap-1 rounded bg-amber-500/15 px-2 py-0.5 text-xs font-semibold text-amber-400"><ShieldOff className="h-3.5 w-3.5" /> Desactivado</span>
                  <span className="text-muted-foreground">Recomendado: protege el acceso aunque roben tu contraseña.</span></>
              )}
            </div>

            {error && <p className="text-sm text-red-400">{error}</p>}

            {/* Idle: botones segun estado */}
            {mode === 'idle' && (
              enabled
                ? <Button variant="outline" onClick={() => { setMode('disable'); setError(null); }}>Desactivar 2FA</Button>
                : <Button onClick={startSetup} disabled={busy}>{busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />} Activar 2FA</Button>
            )}

            {/* Setup: QR + codigo */}
            {mode === 'setup' && (
              <div className="space-y-3 rounded-lg border border-border/60 bg-secondary/20 p-4">
                <p className="text-sm">1. Escanea el código QR con Google/Microsoft Authenticator (o Authy):</p>
                {qr && <img src={qr} alt="Código QR 2FA" className="h-44 w-44 rounded bg-white p-1" />}
                <p className="text-xs text-muted-foreground">¿No puedes escanear? Ingresa esta clave manualmente:</p>
                <code className="block break-all rounded bg-background/60 px-2 py-1 text-xs">{secret}</code>
                <p className="text-sm">2. Ingresa el código de 6 dígitos que muestra la app:</p>
                <div className="flex gap-2">
                  <Input inputMode="numeric" placeholder="123456" className="max-w-[160px] text-center tracking-[0.3em]" value={code} onChange={(e) => setCode(e.target.value)} />
                  <Button onClick={confirmEnable} disabled={busy || code.trim().length < 6}>{busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Check className="h-4 w-4" />} Confirmar</Button>
                  <Button variant="ghost" onClick={reset}>Cancelar</Button>
                </div>
              </div>
            )}

            {/* Backup codes (una sola vez) */}
            {mode === 'backup' && (
              <div className="space-y-3 rounded-lg border border-neon/40 bg-neon/5 p-4">
                <p className="text-sm font-medium text-neon">¡2FA activado! Guarda tus códigos de respaldo.</p>
                <p className="text-xs text-muted-foreground">Cada código sirve UNA vez si pierdes el acceso a tu app. No se volverán a mostrar.</p>
                <div className="grid grid-cols-2 gap-1.5 font-mono text-sm">
                  {backup.map((c) => <span key={c} className="rounded bg-background/60 px-2 py-1 text-center">{c}</span>)}
                </div>
                <div className="flex gap-2">
                  <Button variant="outline" size="sm" onClick={copyBackup}>{copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />} {copied ? 'Copiados' : 'Copiar'}</Button>
                  <Button size="sm" onClick={() => { reset(); reload(); }}>Ya los guardé</Button>
                </div>
              </div>
            )}

            {/* Disable: password + codigo */}
            {mode === 'disable' && (
              <div className="space-y-3 rounded-lg border border-border/60 bg-secondary/20 p-4">
                <p className="text-sm">Para desactivar el 2FA confirma tu contraseña y un código actual:</p>
                <Input type="password" placeholder="Contraseña actual" value={password} onChange={(e) => setPassword(e.target.value)} />
                <Input inputMode="numeric" placeholder="Código 2FA o de respaldo" value={code} onChange={(e) => setCode(e.target.value)} />
                <div className="flex gap-2">
                  <Button variant="destructive" onClick={confirmDisable} disabled={busy || !password || code.trim().length < 6}>{busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldOff className="h-4 w-4" />} Desactivar</Button>
                  <Button variant="ghost" onClick={reset}>Cancelar</Button>
                </div>
              </div>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}

function PasswordCard() {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  async function submit() {
    setMsg(null);
    if (next.length < 8) { setMsg({ ok: false, text: 'La nueva contraseña debe tener al menos 8 caracteres' }); return; }
    if (next !== confirm) { setMsg({ ok: false, text: 'Las contraseñas no coinciden' }); return; }
    setBusy(true);
    try {
      const { token } = await usersApi.changeOwnPassword(current, next);
      // El cambio revoco las sesiones; guardamos el token fresco de esta.
      if (token) tokenStorage.set(token);
      setMsg({ ok: true, text: 'Contraseña actualizada. Se cerraron las demás sesiones.' });
      setCurrent(''); setNext(''); setConfirm('');
    } catch (e) { setMsg({ ok: false, text: errMsg(e, 'No se pudo cambiar la contraseña') }); }
    finally { setBusy(false); }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><Lock className="h-4 w-4 text-neon" /> Cambiar contraseña</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="space-y-1.5">
          <Label>Contraseña actual</Label>
          <Input type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} />
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label>Nueva contraseña</Label>
            <Input type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} />
          </div>
          <div className="space-y-1.5">
            <Label>Confirmar</Label>
            <Input type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
          </div>
        </div>
        {msg && <p className={msg.ok ? 'text-sm text-neon' : 'text-sm text-red-400'}>{msg.text}</p>}
        <Button onClick={submit} disabled={busy || !current || !next}>{busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Check className="h-4 w-4" />} Actualizar contraseña</Button>
      </CardContent>
    </Card>
  );
}
