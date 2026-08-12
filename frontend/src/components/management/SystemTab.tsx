/** Estado del sistema + cambio de contrasena propia. */
import { useEffect, useState, type FormEvent } from 'react';
import { AxiosError } from 'axios';
import {
  Database,
  Search,
  Server,
  Mail,
  Send,
  CheckCircle2,
  XCircle,
  Clock,
  CalendarClock,
  KeyRound,
} from 'lucide-react';
import { systemApi, type SystemStatus } from '@/lib/system';
import { usersApi } from '@/lib/users';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Button } from '@/components/ui/button';

function StatusRow({ icon, label, ok, detail }: { icon: React.ReactNode; label: string; ok: boolean; detail?: string }) {
  return (
    <div className="flex items-center gap-3 rounded-lg border border-border/60 bg-card/40 px-3 py-2.5">
      {icon}
      <div className="min-w-0 flex-1">
        <p className="text-sm">{label}</p>
        {detail && <p className="truncate text-[11px] text-muted-foreground">{detail}</p>}
      </div>
      {ok ? (
        <span className="flex items-center gap-1 text-xs text-emerald-600"><CheckCircle2 className="h-4 w-4" /> OK</span>
      ) : (
        <span className="flex items-center gap-1 text-xs text-red-600"><XCircle className="h-4 w-4" /> Sin conexión</span>
      )}
    </div>
  );
}

export function SystemTab({ onFlash }: { onFlash: (k: 'ok' | 'err', t: string) => void }) {
  const [status, setStatus] = useState<SystemStatus | null>(null);

  useEffect(() => {
    systemApi.status().then(setStatus).catch(() => onFlash('err', 'No se pudo cargar el estado'));
  }, []);

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle className="text-muted-foreground">Estado de conexiones</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {status ? (
            <>
              <StatusRow icon={<Database className="h-4 w-4 text-neon" />} label="Base de datos (PostgreSQL)" ok={status.database} />
              <StatusRow icon={<Search className="h-4 w-4 text-neon" />} label="Wazuh Indexer" ok={status.indexer.reachable} detail={status.indexer.url ?? undefined} />
              <StatusRow icon={<Server className="h-4 w-4 text-neon" />} label="Wazuh API" ok={status.wazuhApi.reachable} detail={status.wazuhApi.url ?? undefined} />
              <StatusRow icon={<Mail className="h-4 w-4 text-neon" />} label="Correo (SMTP)" ok={status.channels.email.configured} detail={status.channels.email.configured ? 'Configurado' : 'Pendiente de credenciales'} />
              <StatusRow icon={<Send className="h-4 w-4 text-neon" />} label="Telegram" ok={status.channels.telegram.configured} detail={status.channels.telegram.configured ? 'Configurado' : 'Pendiente de token'} />
            </>
          ) : (
            <p className="text-sm text-muted-foreground">Cargando…</p>
          )}
        </CardContent>
      </Card>

      <div className="space-y-4">
        <Card>
          <CardHeader>
            <CardTitle className="text-muted-foreground">Tareas programadas</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {status && (
              <>
                <div className="flex items-center gap-3 rounded-lg border border-border/60 bg-card/40 px-3 py-2.5">
                  <Clock className="h-4 w-4 text-neon" />
                  <div className="flex-1 text-sm">Evaluación de notificaciones</div>
                  <span className="text-xs text-muted-foreground">cada {status.scheduler.notifications.interval}</span>
                </div>
                <div className="flex items-center gap-3 rounded-lg border border-border/60 bg-card/40 px-3 py-2.5">
                  <CalendarClock className="h-4 w-4 text-neon" />
                  <div className="flex-1 text-sm">Reporte programado</div>
                  <span className="text-xs text-muted-foreground">
                    {status.scheduler.reports.enabled ? `${status.scheduler.reports.cron} · ${status.scheduler.reports.range}` : 'deshabilitado'}
                  </span>
                </div>
              </>
            )}
          </CardContent>
        </Card>

        <ChangePassword onFlash={onFlash} />
      </div>
    </div>
  );
}

function ChangePassword({ onFlash }: { onFlash: (k: 'ok' | 'err', t: string) => void }) {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [saving, setSaving] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setSaving(true);
    try {
      await usersApi.changeOwnPassword(current, next);
      setCurrent('');
      setNext('');
      onFlash('ok', 'Contraseña actualizada');
    } catch (err) {
      onFlash('err', (err as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo cambiar');
    } finally {
      setSaving(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-muted-foreground">
          <KeyRound className="h-4 w-4" /> Cambiar mi contraseña
        </CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} className="space-y-3">
          <div className="space-y-2">
            <Label>Contraseña actual</Label>
            <Input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} required />
          </div>
          <div className="space-y-2">
            <Label>Nueva contraseña (mín. 8)</Label>
            <Input type="password" value={next} onChange={(e) => setNext(e.target.value)} required minLength={8} />
          </div>
          <div className="flex justify-end">
            <Button type="submit" disabled={saving}>{saving ? 'Guardando…' : 'Actualizar'}</Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}
