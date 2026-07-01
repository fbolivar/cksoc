/**
 * Pantalla de inicio de sesion con identidad PNNC.
 * Soporta 2FA: si la cuenta tiene segundo factor, tras validar la contrasena
 * se solicita el codigo del autenticador (o un codigo de respaldo).
 */
import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { AxiosError } from 'axios';
import { ShieldCheck, Loader2, KeyRound, ArrowLeft } from 'lucide-react';
import { useAuth } from '@/lib/auth';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

export default function Login() {
  const { login, loginVerify2fa } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  // Paso 2 (2FA): si hay challenge, se pide el codigo del autenticador.
  const [challenge, setChallenge] = useState<string | null>(null);
  const [code, setCode] = useState('');

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const step = await login(email, password);
      if (step.twoFactor) {
        setChallenge(step.challenge);
      } else {
        navigate('/', { replace: true });
      }
    } catch (err) {
      const ax = err as AxiosError<{ error?: string }>;
      setError(ax.response?.data?.error ?? 'No se pudo iniciar sesion');
    } finally {
      setLoading(false);
    }
  }

  async function onSubmit2fa(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await loginVerify2fa(challenge!, code.trim());
      navigate('/', { replace: true });
    } catch (err) {
      const ax = err as AxiosError<{ error?: string }>;
      setError(ax.response?.data?.error ?? 'Código inválido');
    } finally {
      setLoading(false);
    }
  }

  function cancel2fa() {
    setChallenge(null);
    setCode('');
    setError(null);
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      {/* Franja tricolor gov.co en el borde superior de la pantalla */}
      <div className="gov-strip fixed inset-x-0 top-0" />
      <div className="w-full max-w-md">
        {/* Encabezado institucional */}
        <div className="flex flex-col items-center text-center mb-8">
          <img
            src="/logo-pnnc.png"
            alt="Parques Nacionales Naturales de Colombia"
            className="h-16 w-auto object-contain mb-4 drop-shadow"
            onError={(e) => ((e.currentTarget as HTMLImageElement).style.display = 'none')}
          />
          <div className="flex items-center gap-2 text-neon">
            <ShieldCheck className="h-5 w-5" />
            <span className="text-xs font-semibold tracking-[0.2em] uppercase">
              Centro de Operaciones de Seguridad
            </span>
          </div>
          <h1 className="mt-2 text-2xl font-semibold">Parques Nacionales Naturales</h1>
          <p className="text-sm text-muted-foreground">Plataforma de monitoreo y respuesta</p>
        </div>

        {!challenge ? (
          <form onSubmit={onSubmit} className="glass rounded-lg p-6 space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email">Correo institucional</Label>
              <Input
                id="email"
                type="email"
                autoComplete="username"
                placeholder="usuario@parquesnacionales.gov.co"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Contrasena</Label>
              <Input
                id="password"
                type="password"
                autoComplete="current-password"
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>

            {error && (
              <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive-foreground">
                {error}
              </div>
            )}

            <Button type="submit" size="lg" className="w-full" disabled={loading}>
              {loading && <Loader2 className="h-4 w-4 animate-spin" />}
              {loading ? 'Ingresando…' : 'Iniciar sesion'}
            </Button>
          </form>
        ) : (
          <form onSubmit={onSubmit2fa} className="glass rounded-lg p-6 space-y-4">
            <div className="flex items-center gap-2 text-neon">
              <KeyRound className="h-5 w-5" />
              <span className="text-sm font-semibold">Verificación en dos pasos</span>
            </div>
            <p className="text-sm text-muted-foreground">
              Ingresa el código de 6 dígitos de tu app autenticadora. ¿Sin acceso? Usa un código de respaldo.
            </p>
            <div className="space-y-2">
              <Label htmlFor="code">Código</Label>
              <Input
                id="code"
                inputMode="numeric"
                autoComplete="one-time-code"
                autoFocus
                placeholder="123456"
                className="text-center text-lg tracking-[0.3em]"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                required
              />
            </div>

            {error && (
              <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive-foreground">
                {error}
              </div>
            )}

            <Button type="submit" size="lg" className="w-full" disabled={loading}>
              {loading && <Loader2 className="h-4 w-4 animate-spin" />}
              {loading ? 'Verificando…' : 'Verificar e ingresar'}
            </Button>
            <button
              type="button"
              onClick={cancel2fa}
              className="flex w-full items-center justify-center gap-1 text-xs text-muted-foreground hover:text-foreground"
            >
              <ArrowLeft className="h-3 w-3" /> Volver
            </button>
          </form>
        )}

        <p className="mt-6 text-center text-[11px] text-muted-foreground/60">
          Acceso restringido a personal autorizado · Parques Nacionales Naturales de Colombia
        </p>
      </div>
    </div>
  );
}
