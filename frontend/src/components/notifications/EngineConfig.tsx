/**
 * Configuracion del motor de correo: destinatarios, hora del resumen,
 * activar/desactivar inmediatas/digest, tope diario, y botones de prueba.
 */
import { useEffect, useState } from 'react';
import { AxiosError } from 'axios';
import { Mail, Send, Save, FileText, Zap, ShieldAlert } from 'lucide-react';
import {
  notificationsApi,
  type NotifySettings,
  type DailyStatus,
  type ChannelStatus,
} from '@/lib/notifications';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Switch } from '@/components/ui/switch';
import { Badge } from '@/components/ui/badge';

export function EngineConfig({
  canManage,
  onFlash,
}: {
  canManage: boolean;
  onFlash: (k: 'ok' | 'err', t: string) => void;
}) {
  const [settings, setSettings] = useState<NotifySettings | null>(null);
  const [daily, setDaily] = useState<DailyStatus | null>(null);
  const [channels, setChannels] = useState<ChannelStatus | null>(null);
  const [recipients, setRecipients] = useState('');
  const [busy, setBusy] = useState<string | null>(null);

  async function load() {
    const d = await notificationsApi.getSettings();
    setSettings(d.settings);
    setDaily(d.daily);
    setChannels(d.channels);
    setRecipients(d.settings.recipients.join('\n'));
  }
  useEffect(() => {
    load().catch(() => onFlash('err', 'No se pudo cargar la configuración'));
  }, []);

  const err = (e: unknown) =>
    onFlash('err', (e as AxiosError<{ error?: string }>).response?.data?.error ?? 'Error');

  async function save() {
    if (!settings) return;
    setBusy('save');
    try {
      const list = recipients.split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
      const s = await notificationsApi.updateSettings({ ...settings, recipients: list });
      setSettings(s);
      onFlash('ok', 'Configuración guardada');
    } catch (e) {
      err(e);
    } finally {
      setBusy(null);
    }
  }

  async function action(kind: 'digest' | 'immediate') {
    setBusy(kind);
    try {
      if (kind === 'digest') await notificationsApi.sendDigest();
      else await notificationsApi.testImmediate();
      await load();
      onFlash('ok', kind === 'digest' ? 'Resumen enviado' : 'Alerta de prueba enviada');
    } catch (e) {
      err(e);
    } finally {
      setBusy(null);
    }
  }

  if (!settings || !daily) return null;
  const pct = Math.min(100, Math.round((daily.sent / daily.cap) * 100));

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0">
        <CardTitle className="flex items-center gap-2 text-muted-foreground">
          <Mail className="h-4 w-4" /> Motor de correo
        </CardTitle>
        <div className="flex items-center gap-2">
          {channels?.email.configured ? (
            <Badge variant="success">SMTP configurado</Badge>
          ) : (
            <Badge variant="warning">SMTP pendiente</Badge>
          )}
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Tope diario */}
        <div>
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>Correos enviados hoy</span>
            <span className={daily.capReached ? 'text-red-400' : ''}>
              {daily.sent} / {daily.cap}
            </span>
          </div>
          <div className="mt-1 h-2 w-full overflow-hidden rounded-full bg-muted">
            <div
              className="h-full rounded-full transition-all"
              style={{ width: `${pct}%`, background: daily.capReached ? '#ef4444' : '#03A64A' }}
            />
          </div>
        </div>

        {/* Toggles */}
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="flex items-center justify-between rounded-md border border-border/60 bg-card/40 px-3 py-2.5">
            <span className="flex items-center gap-2 text-sm"><ShieldAlert className="h-4 w-4 text-neon" /> Alertas inmediatas</span>
            <Switch checked={settings.immediateEnabled} disabled={!canManage}
              onChange={(v) => setSettings({ ...settings, immediateEnabled: v })} />
          </div>
          <div className="flex items-center justify-between rounded-md border border-border/60 bg-card/40 px-3 py-2.5">
            <span className="flex items-center gap-2 text-sm"><FileText className="h-4 w-4 text-neon" /> Resumen diario</span>
            <Switch checked={settings.digestEnabled} disabled={!canManage}
              onChange={(v) => setSettings({ ...settings, digestEnabled: v })} />
          </div>
        </div>

        <div className="grid gap-3 sm:grid-cols-3">
          <div className="space-y-2 sm:col-span-2">
            <Label>Destinatarios (uno por línea)</Label>
            <Textarea value={recipients} onChange={(e) => setRecipients(e.target.value)}
              disabled={!canManage} placeholder="redes.seguridad@parquesnacionales.gov.co" />
          </div>
          <div className="space-y-2">
            <Label>Hora del resumen (0–23)</Label>
            <Input type="number" min={0} max={23} value={settings.digestHour} disabled={!canManage}
              onChange={(e) => setSettings({ ...settings, digestHour: Number(e.target.value) })} />
            <p className="text-[10px] text-muted-foreground">Zona horaria América/Bogotá</p>
          </div>
        </div>

        {canManage && (
          <div className="flex flex-wrap items-center gap-2 border-t border-border/50 pt-3">
            <Button size="sm" onClick={save} disabled={busy === 'save'}>
              <Save className="h-4 w-4" /> Guardar
            </Button>
            <Button size="sm" variant="outline" onClick={() => action('digest')} disabled={!!busy}>
              <FileText className="h-4 w-4" /> Enviar resumen ahora
            </Button>
            <Button size="sm" variant="outline" onClick={() => action('immediate')} disabled={!!busy}>
              <Zap className="h-4 w-4" /> Probar alerta crítica
            </Button>
            <span className="ml-auto text-[11px] text-muted-foreground">
              <Send className="mr-1 inline h-3 w-3" />
              Inmediato: nivel ≥12, fuerza bruta VPN, IP maliciosa · Digest 8 AM
            </span>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
