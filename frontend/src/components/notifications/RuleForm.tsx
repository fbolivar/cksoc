/** Formulario de creacion/edicion de una regla de notificacion. */
import { useState, type FormEvent } from 'react';
import { Mail, Send, X } from 'lucide-react';
import type { AlertRule, Channel, ChannelStatus, RuleInput } from '@/lib/notifications';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { cn } from '@/lib/utils';

const toLines = (arr: string[]) => arr.join('\n');
const fromLines = (s: string) =>
  s
    .split(/[\n,]/)
    .map((x) => x.trim())
    .filter(Boolean);

export function RuleForm({
  initial,
  channels: chStatus,
  onSubmit,
  onCancel,
}: {
  initial?: AlertRule;
  channels: ChannelStatus;
  onSubmit: (input: RuleInput) => Promise<void>;
  onCancel: () => void;
}) {
  const [name, setName] = useState(initial?.name ?? '');
  const [description, setDescription] = useState(initial?.description ?? '');
  const [minLevel, setMinLevel] = useState(initial?.minLevel ?? 10);
  const [threshold, setThreshold] = useState(initial?.threshold ?? 1);
  const [windowMinutes, setWindowMinutes] = useState(initial?.windowMinutes ?? 5);
  const [cooldownMinutes, setCooldownMinutes] = useState(initial?.cooldownMinutes ?? 15);
  const [ruleGroups, setRuleGroups] = useState(toLines(initial?.ruleGroups ?? []));
  const [channels, setChannels] = useState<Channel[]>(initial?.channels ?? ['email']);
  const [emails, setEmails] = useState(toLines(initial?.emailRecipients ?? []));
  const [chatIds, setChatIds] = useState(toLines(initial?.telegramChatIds ?? []));
  const [enabled, setEnabled] = useState(initial?.enabled ?? true);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const toggleChannel = (c: Channel) =>
    setChannels((prev) => (prev.includes(c) ? prev.filter((x) => x !== c) : [...prev, c]));

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSaving(true);
    try {
      await onSubmit({
        name,
        description: description || undefined,
        minLevel: Number(minLevel),
        threshold: Number(threshold),
        windowMinutes: Number(windowMinutes),
        cooldownMinutes: Number(cooldownMinutes),
        ruleGroups: fromLines(ruleGroups),
        channels,
        emailRecipients: fromLines(emails),
        telegramChatIds: fromLines(chatIds),
        enabled,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'No se pudo guardar la regla');
    } finally {
      setSaving(false);
    }
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0">
        <CardTitle>{initial ? 'Editar regla' : 'Nueva regla'}</CardTitle>
        <Button variant="ghost" size="icon" onClick={onCancel} type="button">
          <X className="h-4 w-4" />
        </Button>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2 sm:col-span-2">
              <Label htmlFor="rname">Nombre</Label>
              <Input id="rname" value={name} onChange={(e) => setName(e.target.value)} required
                placeholder="Ej: Alertas criticas de seguridad" />
            </div>
            <div className="space-y-2 sm:col-span-2">
              <Label htmlFor="rdesc">Descripción (opcional)</Label>
              <Input id="rdesc" value={description} onChange={(e) => setDescription(e.target.value)}
                placeholder="Que detecta esta regla" />
            </div>
          </div>

          <div className="grid gap-4 sm:grid-cols-4">
            <Field label="Nivel mínimo" hint="0–15">
              <Input type="number" min={0} max={15} value={minLevel}
                onChange={(e) => setMinLevel(+e.target.value)} />
            </Field>
            <Field label="Umbral" hint="nº alertas">
              <Input type="number" min={1} value={threshold}
                onChange={(e) => setThreshold(+e.target.value)} />
            </Field>
            <Field label="Ventana" hint="minutos">
              <Input type="number" min={1} value={windowMinutes}
                onChange={(e) => setWindowMinutes(+e.target.value)} />
            </Field>
            <Field label="Cooldown" hint="minutos">
              <Input type="number" min={0} value={cooldownMinutes}
                onChange={(e) => setCooldownMinutes(+e.target.value)} />
            </Field>
          </div>

          <div className="space-y-2">
            <Label>Grupos de regla (opcional, uno por línea)</Label>
            <Textarea value={ruleGroups} onChange={(e) => setRuleGroups(e.target.value)}
              placeholder="authentication_failed&#10;web_attack" />
          </div>

          {/* Canales */}
          <div className="space-y-2">
            <Label>Canales de notificación</Label>
            <div className="flex flex-wrap gap-2">
              <ChannelToggle
                active={channels.includes('email')}
                onClick={() => toggleChannel('email')}
                icon={<Mail className="h-4 w-4" />}
                label="Correo"
                warn={!chStatus.email.configured}
              />
              <ChannelToggle
                active={channels.includes('telegram')}
                onClick={() => toggleChannel('telegram')}
                icon={<Send className="h-4 w-4" />}
                label="Telegram"
                warn={!chStatus.telegram.configured}
              />
            </div>
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            {channels.includes('email') && (
              <div className="space-y-2">
                <Label>Correos destino (uno por línea)</Label>
                <Textarea value={emails} onChange={(e) => setEmails(e.target.value)}
                  placeholder="analista@parquesnacionales.gov.co" />
              </div>
            )}
            {channels.includes('telegram') && (
              <div className="space-y-2">
                <Label>Chat IDs de Telegram (uno por línea)</Label>
                <Textarea value={chatIds} onChange={(e) => setChatIds(e.target.value)}
                  placeholder="-1001234567890" />
              </div>
            )}
          </div>

          <div className="flex items-center gap-2">
            <Switch checked={enabled} onChange={setEnabled} />
            <span className="text-sm text-muted-foreground">Regla activa</span>
          </div>

          {error && (
            <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {error}
            </div>
          )}

          <div className="flex justify-end gap-2">
            <Button type="button" variant="outline" onClick={onCancel}>Cancelar</Button>
            <Button type="submit" disabled={saving}>{saving ? 'Guardando…' : 'Guardar regla'}</Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="space-y-2">
      <Label>
        {label} {hint && <span className="text-muted-foreground/50">· {hint}</span>}
      </Label>
      {children}
    </div>
  );
}

function ChannelToggle({
  active,
  onClick,
  icon,
  label,
  warn,
}: {
  active: boolean;
  onClick: () => void;
  icon: React.ReactNode;
  label: string;
  warn?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        'flex items-center gap-2 rounded-md border px-3 py-2 text-sm transition-colors',
        active
          ? 'border-primary/40 bg-primary/15 text-foreground'
          : 'border-border bg-card/40 text-muted-foreground hover:text-foreground'
      )}
    >
      {icon}
      {label}
      {active && warn && (
        <span className="text-[10px] text-amber-400" title="Canal sin credenciales configuradas">
          ⚠ sin configurar
        </span>
      )}
    </button>
  );
}
