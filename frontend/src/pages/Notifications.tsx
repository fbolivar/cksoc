/**
 * Pagina de Notificaciones (Fase 3).
 * Estado de canales, gestion de reglas (CRUD), prueba de envio,
 * evaluacion manual e historial de notificaciones.
 */
import { useEffect, useState } from 'react';
import { AxiosError } from 'axios';
import {
  BellRing,
  Mail,
  Send,
  Plus,
  Pencil,
  Trash2,
  Zap,
  CheckCircle2,
  XCircle,
  Clock,
} from 'lucide-react';
import { useAuth } from '@/lib/auth';
import {
  notificationsApi,
  type AlertRule,
  type ChannelStatus,
  type LogEntry,
  type RuleInput,
  type Channel,
} from '@/lib/notifications';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { Input } from '@/components/ui/input';
import { RuleForm } from '@/components/notifications/RuleForm';
import { EngineConfig } from '@/components/notifications/EngineConfig';

export default function Notifications() {
  const { user } = useAuth();
  const canManage = user?.role === 'admin' || user?.role === 'analista';

  const [rules, setRules] = useState<AlertRule[]>([]);
  const [channels, setChannels] = useState<ChannelStatus | null>(null);
  const [log, setLog] = useState<LogEntry[]>([]);
  const [editing, setEditing] = useState<AlertRule | null>(null);
  const [creating, setCreating] = useState(false);
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  async function reload() {
    const [data, logData] = await Promise.all([
      notificationsApi.list(),
      notificationsApi.log().catch(() => []),
    ]);
    setRules(data.rules);
    setChannels(data.channels);
    setLog(logData);
  }

  useEffect(() => {
    reload().catch(() => setMsg({ kind: 'err', text: 'No se pudieron cargar las notificaciones' }));
  }, []);

  const flash = (kind: 'ok' | 'err', text: string) => {
    setMsg({ kind, text });
    setTimeout(() => setMsg(null), 4000);
  };

  async function saveRule(input: RuleInput) {
    if (editing) await notificationsApi.update(editing.id, input);
    else await notificationsApi.create(input);
    setEditing(null);
    setCreating(false);
    await reload();
    flash('ok', 'Regla guardada');
  }

  async function toggleRule(rule: AlertRule) {
    try {
      await notificationsApi.update(rule.id, { ...rule, description: rule.description ?? undefined });
      await reload();
    } catch {
      flash('err', 'No se pudo cambiar el estado');
    }
  }

  async function removeRule(rule: AlertRule) {
    if (!confirm(`¿Eliminar la regla "${rule.name}"?`)) return;
    await notificationsApi.remove(rule.id);
    await reload();
    flash('ok', 'Regla eliminada');
  }

  async function evaluateNow() {
    try {
      await notificationsApi.evaluateNow();
      await reload();
      flash('ok', 'Evaluación ejecutada');
    } catch (err) {
      flash('err', (err as AxiosError<{ error?: string }>).response?.data?.error ?? 'Error');
    }
  }

  return (
    <div className="mx-auto max-w-6xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
            <BellRing className="h-6 w-6 text-neon" /> Notificaciones
          </h1>
          <p className="text-sm text-muted-foreground">
            Reglas que avisan por correo y Telegram según las alertas de Wazuh
          </p>
        </div>
        {canManage && (
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={evaluateNow}>
              <Zap className="h-4 w-4" /> Evaluar ahora
            </Button>
            <Button size="sm" onClick={() => { setCreating(true); setEditing(null); }}>
              <Plus className="h-4 w-4" /> Nueva regla
            </Button>
          </div>
        )}
      </div>

      {msg && (
        <div
          className={`rounded-md border px-3 py-2 text-sm ${
            msg.kind === 'ok'
              ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200'
              : 'border-destructive/40 bg-destructive/10 text-destructive'
          }`}
        >
          {msg.text}
        </div>
      )}

      {/* Motor de correo (config + tope + pruebas) */}
      <EngineConfig canManage={canManage} onFlash={flash} />

      {/* Estado de canales */}
      {channels && <ChannelsPanel channels={channels} canManage={canManage} onFlash={flash} />}

      {/* Formulario */}
      {(creating || editing) && channels && (
        <RuleForm
          initial={editing ?? undefined}
          channels={channels}
          onSubmit={saveRule}
          onCancel={() => { setCreating(false); setEditing(null); }}
        />
      )}

      {/* Lista de reglas */}
      <Card>
        <CardHeader>
          <CardTitle className="text-muted-foreground">Reglas configuradas ({rules.length})</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {rules.length === 0 && (
            <p className="py-6 text-center text-sm text-muted-foreground">
              No hay reglas todavía. {canManage && 'Crea la primera con “Nueva regla”.'}
            </p>
          )}
          {rules.map((rule) => (
            <div
              key={rule.id}
              className="flex flex-wrap items-center gap-3 rounded-lg border border-border/50 bg-card/40 p-4"
            >
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="font-medium">{rule.name}</span>
                  {rule.channels.includes('email') && (
                    <Badge variant="muted"><Mail className="h-3 w-3" /> correo</Badge>
                  )}
                  {rule.channels.includes('telegram') && (
                    <Badge variant="muted"><Send className="h-3 w-3" /> telegram</Badge>
                  )}
                </div>
                <p className="mt-1 text-xs text-muted-foreground">
                  Nivel ≥ <b>{rule.minLevel}</b> · umbral <b>{rule.threshold}</b> · ventana{' '}
                  <b>{rule.windowMinutes}m</b> · cooldown <b>{rule.cooldownMinutes}m</b>
                  {rule.ruleGroups.length > 0 && <> · grupos: {rule.ruleGroups.join(', ')}</>}
                </p>
                {rule.lastTriggeredAt && (
                  <p className="mt-0.5 text-[11px] text-muted-foreground/70">
                    Último disparo: {new Date(rule.lastTriggeredAt).toLocaleString('es-CO')}
                  </p>
                )}
              </div>
              <div className="flex items-center gap-2">
                <Switch
                  checked={rule.enabled}
                  onChange={() => toggleRule({ ...rule, enabled: !rule.enabled })}
                  disabled={!canManage}
                />
                {canManage && (
                  <>
                    <Button variant="ghost" size="icon" onClick={() => { setEditing(rule); setCreating(false); }}>
                      <Pencil className="h-4 w-4" />
                    </Button>
                    <Button variant="ghost" size="icon" onClick={() => removeRule(rule)}>
                      <Trash2 className="h-4 w-4 text-red-400" />
                    </Button>
                  </>
                )}
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      {/* Historial */}
      <Card>
        <CardHeader>
          <CardTitle className="text-muted-foreground">Historial de notificaciones</CardTitle>
        </CardHeader>
        <CardContent>
          {log.length === 0 ? (
            <p className="py-4 text-center text-sm text-muted-foreground">Sin envíos registrados</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border/60 text-left text-xs text-muted-foreground">
                    <th className="pb-2 pr-4 font-medium">Fecha</th>
                    <th className="pb-2 pr-4 font-medium">Regla</th>
                    <th className="pb-2 pr-4 font-medium">Canal</th>
                    <th className="pb-2 pr-4 font-medium">Destinos</th>
                    <th className="pb-2 font-medium">Estado</th>
                  </tr>
                </thead>
                <tbody>
                  {log.map((e) => (
                    <tr key={e.id} className="border-b border-border/30 last:border-0">
                      <td className="py-2 pr-4 text-muted-foreground">
                        {new Date(e.created_at).toLocaleString('es-CO')}
                      </td>
                      <td className="py-2 pr-4">{e.rule_name ?? '—'}</td>
                      <td className="py-2 pr-4">{e.channel}</td>
                      <td className="py-2 pr-4 text-muted-foreground">{e.recipients.join(', ')}</td>
                      <td className="py-2">
                        {e.status === 'sent' ? (
                          <Badge variant="success"><CheckCircle2 className="h-3 w-3" /> enviado</Badge>
                        ) : (
                          <Badge variant="danger" >
                            <XCircle className="h-3 w-3" /> falló
                          </Badge>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function ChannelsPanel({
  channels,
  canManage,
  onFlash,
}: {
  channels: ChannelStatus;
  canManage: boolean;
  onFlash: (k: 'ok' | 'err', t: string) => void;
}) {
  const [testChannel, setTestChannel] = useState<Channel>('email');
  const [target, setTarget] = useState('');
  const [busy, setBusy] = useState(false);

  async function sendTest() {
    setBusy(true);
    try {
      await notificationsApi.test(testChannel, target);
      onFlash('ok', 'Mensaje de prueba enviado');
    } catch (err) {
      onFlash('err', (err as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo enviar');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-muted-foreground">Canales</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap gap-3">
          <ChannelBadge icon={<Mail className="h-4 w-4" />} label="Correo (SMTP)" ok={channels.email.configured} />
          <ChannelBadge icon={<Send className="h-4 w-4" />} label="Telegram" ok={channels.telegram.configured} />
        </div>

        {canManage && (
          <div className="flex flex-wrap items-end gap-2 border-t border-border/50 pt-4">
            <div className="space-y-1">
              <label className="text-xs text-muted-foreground">Probar canal</label>
              <select
                value={testChannel}
                onChange={(e) => setTestChannel(e.target.value as Channel)}
                className="h-10 rounded-md border border-input bg-background/60 px-3 text-sm"
              >
                <option value="email">Correo</option>
                <option value="telegram">Telegram</option>
              </select>
            </div>
            <div className="flex-1 space-y-1" style={{ minWidth: 220 }}>
              <label className="text-xs text-muted-foreground">
                {testChannel === 'email' ? 'Correo destino' : 'Chat ID'}
              </label>
              <Input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder={testChannel === 'email' ? 'tu@correo.gov.co' : '-1001234567890'}
              />
            </div>
            <Button onClick={sendTest} disabled={busy || !target}>
              <Send className="h-4 w-4" /> Enviar prueba
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function ChannelBadge({ icon, label, ok }: { icon: React.ReactNode; label: string; ok: boolean }) {
  return (
    <div className="flex items-center gap-2 rounded-lg border border-border/60 bg-card/40 px-3 py-2">
      {icon}
      <span className="text-sm">{label}</span>
      {ok ? (
        <Badge variant="success"><CheckCircle2 className="h-3 w-3" /> configurado</Badge>
      ) : (
        <Badge variant="warning"><Clock className="h-3 w-3" /> pendiente</Badge>
      )}
    </div>
  );
}
