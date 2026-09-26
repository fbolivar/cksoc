/**
 * Anti-BEC — señales de compromiso de correo (Business Email Compromise):
 * reglas de reenvío/ocultamiento (auditoría O365) y URLs/adjuntos maliciosos
 * en correo reciente (Graph). Solo lectura + alerta.
 */
import { useEffect, useState } from 'react';
import { AxiosError } from 'axios';
import {
  MailWarning, RefreshCw, Loader2, ShieldAlert, Forward, Paperclip, CheckCircle2, EyeOff,
} from 'lucide-react';
import { becApi, type BecOverview, type BecFinding, type BecSev } from '@/lib/bec';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

const SEV_COLOR: Record<BecSev, string> = { critica: 'destructive', alta: 'warn-orange', media: 'primary' };
const TIPOS = ['forwarding_rule', 'mailbox_forwarding', 'mail_bad_url', 'mail_bad_attachment'] as const;
const TIPO_LABEL: Record<string, string> = {
  forwarding_rule: 'Regla de reenvío', mailbox_forwarding: 'Reenvío de buzón',
  mail_bad_url: 'URL maliciosa', mail_bad_attachment: 'Adjunto malicioso',
};

function SevPill({ sev }: { sev: BecSev }) {
  const c = SEV_COLOR[sev];
  return (
    <span className="hw-mono inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide"
      style={{ background: `hsl(var(--${c}) / .16)`, color: `hsl(var(--${c}))` }}>{sev}</span>
  );
}

export default function Bec() {
  const [ov, setOv] = useState<BecOverview | null>(null);
  const [filtro, setFiltro] = useState<'todas' | (typeof TIPOS)[number]>('todas');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  const flash = (kind: 'ok' | 'err', text: string) => { setMsg({ kind, text }); setTimeout(() => setMsg(null), 5000); };
  const err = (e: unknown, fb: string) => flash('err', (e as AxiosError<{ error?: string }>).response?.data?.error ?? fb);

  async function reload() { setOv(await becApi.overview()); }
  useEffect(() => { reload().catch(() => flash('err', 'No se pudo cargar')); /* eslint-disable-next-line */ }, []);

  async function scan() {
    setBusy(true);
    try { const r = await becApi.scan('7d'); flash('ok', `Análisis completado · ${r.reglas} regla(s), ${r.correoRevisado} correo(s) revisado(s), ${r.nuevos} nuevo(s)`); await reload(); }
    catch (e) { err(e, 'Error en el análisis'); } finally { setBusy(false); }
  }
  async function cerrar(f: BecFinding, estado: 'resolved' | 'dismissed') {
    try { await becApi.setStatus(f.id, estado); await reload(); } catch (e) { err(e, 'No se pudo actualizar'); }
  }

  const s = ov?.severidad;
  const t = ov?.tipo ?? {};
  const reenvios = (t.forwarding_rule ?? 0) + (t.mailbox_forwarding ?? 0);
  const correo = (t.mail_bad_url ?? 0) + (t.mail_bad_attachment ?? 0);
  const findings = ov?.top ?? [];
  const visibles = filtro === 'todas' ? findings : findings.filter((f) => f.tipo === filtro);

  return (
    <div className="mx-auto max-w-5xl space-y-5">
      <div>
        <h1 className="hw-mono flex items-center gap-2 text-2xl font-bold tracking-tight">
          <MailWarning className="h-6 w-6 text-primary" /> CORREO · ANTI-BEC
        </h1>
        <p className="hw-mono text-[11px] tracking-wide text-muted-foreground">
          REENVÍOS // REGLAS OCULTAS // URLs Y ADJUNTOS MALICIOSOS
        </p>
      </div>

      {msg && (
        <div className={`rounded-md border px-3 py-2 text-sm ${msg.kind === 'ok'
          ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200'
          : 'border-destructive/40 bg-destructive/10 text-destructive'}`}>{msg.text}</div>
      )}

      <div className="grid gap-3 sm:grid-cols-4">
        {[
          { icon: ShieldAlert, col: 'destructive', v: s?.critica ?? 0, l: 'Críticas' },
          { icon: ShieldAlert, col: 'warn-orange', v: s?.alta ?? 0, l: 'Altas' },
          { icon: Forward, col: 'cyan', v: reenvios, l: 'Reenvíos / reglas' },
          { icon: Paperclip, col: 'primary', v: correo, l: 'URLs / adjuntos malos' },
        ].map((k) => (
          <div key={k.l} className="hud">
            <span className="hw-clip mb-2 flex h-9 w-9 items-center justify-center"
              style={{ background: `hsl(var(--${k.col}) / .14)`, color: `hsl(var(--${k.col}))` }}>
              <k.icon className="h-[18px] w-[18px]" />
            </span>
            <div className="text-2xl font-bold">{k.v.toLocaleString('es-CO')}</div>
            <div className="text-[12px] text-muted-foreground">{k.l}</div>
          </div>
        ))}
      </div>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <CardTitle className="text-muted-foreground">Señales de BEC ({findings.length})</CardTitle>
          <div className="flex flex-wrap items-center gap-1">
            {(['todas', ...TIPOS] as const).map((x) => (
              <Button key={x} size="sm" variant={filtro === x ? 'default' : 'ghost'} className="h-7 px-2 text-[11px]" onClick={() => setFiltro(x)}>
                {x === 'todas' ? 'Todas' : TIPO_LABEL[x]}
              </Button>
            ))}
            <Button size="sm" variant="outline" className="h-7" onClick={scan} disabled={busy}>
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />} Analizar
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {visibles.length === 0 ? (
            <p className="py-6 text-center text-sm text-muted-foreground">
              Sin señales de BEC abiertas. Ejecuta un análisis — o el correo está limpio. 👍
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border/60 text-left text-xs text-muted-foreground">
                    <th className="pb-2 pr-3 font-medium">Sev.</th>
                    <th className="pb-2 pr-3 font-medium">Tipo</th>
                    <th className="pb-2 pr-3 font-medium">Buzón</th>
                    <th className="pb-2 pr-3 font-medium">Detalle</th>
                    <th className="pb-2 font-medium text-right">Acciones</th>
                  </tr>
                </thead>
                <tbody>
                  {visibles.map((f) => (
                    <tr key={f.id} className="border-b border-border/30 last:border-0 align-top">
                      <td className="py-2.5 pr-3"><SevPill sev={f.severidad} /></td>
                      <td className="py-2.5 pr-3 text-xs text-muted-foreground whitespace-nowrap">{TIPO_LABEL[f.tipo] ?? f.tipo}</td>
                      <td className="py-2.5 pr-3 font-mono text-[12px]">{f.usuario}</td>
                      <td className="py-2.5 pr-3 text-[13px]">{f.detalle}</td>
                      <td className="py-2.5">
                        <div className="flex justify-end gap-1">
                          <Button variant="ghost" size="icon" title="Marcar resuelto" onClick={() => cerrar(f, 'resolved')}>
                            <CheckCircle2 className="h-4 w-4" />
                          </Button>
                          <Button variant="ghost" size="icon" title="Descartar" onClick={() => cerrar(f, 'dismissed')}>
                            <EyeOff className="h-4 w-4" />
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <p className="mt-3 text-[11px] text-muted-foreground">
            Detección de <b>solo lectura</b> (no es un gateway y no modifica ningún correo). Las <b>reglas de reenvío</b>
            salen de la auditoría de M365; las <b>URLs/adjuntos</b> se revisan por Graph en los buzones bajo ataque y se
            cruzan con el catálogo de IOCs. Los avisos por Telegram incluyen la remediación de cada caso.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
