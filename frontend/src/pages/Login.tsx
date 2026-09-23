/**
 * Pantalla de inicio de sesion HexWatch (tema claro, tarjeta blanca).
 * Soporta 2FA: si la cuenta tiene segundo factor, tras validar la contrasena
 * se solicita el codigo del autenticador (o un codigo de respaldo).
 */
import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { AxiosError } from 'axios';
import { Loader2, KeyRound, ArrowLeft } from 'lucide-react';
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
    <div className="min-h-screen flex items-center justify-center p-4 bg-background">
      <div className="w-full max-w-[400px]">
        {/* Marca */}
        <div className="flex flex-col items-center text-center mb-7">
          <img
            src="/logo-cs-lockup.png"
            alt="Click Solutions"
            className="h-14 w-auto object-contain mb-3"
            onError={(e) => ((e.currentTarget as HTMLImageElement).style.display = 'none')}
          />
          <h1 className="text-2xl font-bold tracking-tight text-foreground">HexWatch</h1>
          <p className="mt-1 text-sm text-muted-foreground">Centro de Operaciones de Seguridad</p>
        </div>

        {!challenge ? (
          <form onSubmit={onSubmit} className="glass rounded-[22px] p-7 space-y-5">
            <div>
              <h2 className="text-lg font-semibold text-foreground">Bienvenido de nuevo</h2>
              <p className="text-sm text-muted-foreground">Inicia sesión para continuar</p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="email">Correo</Label>
              <Input
                id="email"
                type="email"
                autoComplete="username"
                placeholder="tucorreo@empresa.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Contraseña</Label>
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
              <div className="rounded-xl border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
                {error}
              </div>
            )}

            <Button type="submit" size="lg" className="w-full" disabled={loading}>
              {loading && <Loader2 className="h-4 w-4 animate-spin" />}
              {loading ? 'Ingresando…' : 'Iniciar sesión'}
            </Button>
          </form>
        ) : (
          <form onSubmit={onSubmit2fa} className="glass rounded-[22px] p-7 space-y-5">
            <div className="flex items-center gap-2 text-primary">
              <KeyRound className="h-5 w-5" />
              <span className="text-base font-semibold">Verificación en dos pasos</span>
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
              <div className="rounded-xl border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
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

        <p className="mt-6 text-center text-[11px] text-muted-foreground/70">
          Acceso restringido a personal autorizado · HexWatch
        </p>
      </div>
    </div>
  );
}
