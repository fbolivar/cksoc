/**
 * Shadow-AI — uso de IA generativa detectado por la red (SNI del SonicWall).
 * Separa el uso aprobado del "shadow AI" no autorizado; visibilidad + alerta.
 */
import { useEffect, useState } from 'react';
import { AxiosError } from 'axios';
import {
  Bot, RefreshCw, Loader2, ShieldCheck, ShieldAlert, Cpu, Users, Activity, Check, Ban,
} from 'lucide-react';
import { shadowAiApi, type AiOverview } from '@/lib/shadowai';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

function Pill({ ok, children }: { ok: boolean; children: React.ReactNode }) {
  return (
    <span className="hw-mono inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide"
      style={{ background: ok ? 'hsl(152 60% 45% / .16)' : 'hsl(var(--destructive) / .16)', color: ok ? 'hsl(152 65% 55%)' : 'hsl(var(--destructive))' }}>
      {children}
    </span>
  );
}

export default function ShadowAi() {
  const [ov, setOv] = useState<AiOverview | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  const flash = (kind: 'ok' | 'err', text: string) => { setMsg({ kind, text }); setTimeout(() => setMsg(null), 5000); };
  const err = (e: unknown, fb: string) => flash('err', (e as AxiosError<{ error?: string }>).response?.data?.error ?? fb);

  async function reload() { setOv(await shadowAiApi.overview()); }
  useEffect(() => { reload().catch(() => flash('err', 'No se pudo cargar')); /* eslint-disable-next-line */ }, []);

  async function scan() {
    setBusy('scan');
    try { const r = await shadowAiApi.scan('7d'); flash('ok', `Escaneo completado · ${r.devices} equipo(s), ${r.services} servicio(s), ${r.nuevos} nuevo(s)`); await reload(); }
    catch (e) { err(e, 'Error en el escaneo'); } finally { setBusy(null); }
  }
  async function togglePolicy(service: string, sanctioned: boolean) {
    setBusy(service);
    try { await shadowAiApi.setPolicy(service, sanctioned); await reload(); flash('ok', sanctioned ? 'Servicio aprobado' : 'Servicio marcado como no autorizado'); }
    catch (e) { err(e, 'No se pudo actualizar'); } finally { setBusy(null); }
  }

  const k = ov?.kpis;
  return (
    <div className="mx-auto max-w-5xl space-y-5">
      <div>
        <h1 className="hw-mono flex items-center gap-2 text-2xl font-bold tracking-tight">
          <Bot className="h-6 w-6 text-primary" /> SHADOW-AI · USO DE IA
        </h1>
        <p className="hw-mono text-[11px] tracking-wide text-muted-foreground">
          DETECCIÓN POR RED (SNI) // IA GENERATIVA // APROBADO vs NO AUTORIZADO
        </p>
      </div>

      {msg && (
        <div className={`rounded-md border px-3 py-2 text-sm ${msg.kind === 'ok'
          ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200'
          : 'border-destructive/40 bg-destructive/10 text-destructive'}`}>{msg.text}</div>
      )}

      {/* KPIs */}
      <div className="grid gap-3 sm:grid-cols-4">
        {[
          { icon: Users, col: 'primary', v: k?.dispositivos ?? 0, l: 'Equipos usando IA' },
          { icon: Cpu, col: 'cyan', v: k?.servicios ?? 0, l: 'Servicios detectados' },
          { icon: ShieldAlert, col: 'destructive', v: k?.shadowDispositivos ?? 0, l: 'Equipos con IA no autorizada' },
          { icon: Activity, col: 'warn-orange', v: k?.shadowHits ?? 0, l: 'Conexiones shadow' },
        ].map((x) => (
          <div key={x.l} className="hud">
            <span className="hw-clip mb-2 flex h-9 w-9 items-center justify-center"
              style={{ background: `hsl(var(--${x.col}) / .14)`, color: `hsl(var(--${x.col}))` }}>
              <x.icon className="h-[18px] w-[18px]" />
            </span>
            <div className="text-2xl font-bold">{x.v.toLocaleString('es-CO')}</div>
            <div className="text-[12px] text-muted-foreground">{x.l}</div>
          </div>
        ))}
      </div>

      {/* Servicios detectados + política */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <CardTitle className="text-muted-foreground">Servicios de IA detectados</CardTitle>
          <Button size="sm" variant="outline" onClick={scan} disabled={!!busy}>
            {busy === 'scan' ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />} Escanear red
          </Button>
        </CardHeader>
        <CardContent>
          {!ov || ov.services.length === 0 ? (
            <p className="py-6 text-center text-sm text-muted-foreground">
              No se ha detectado uso de IA generativa en la red. Ejecuta un escaneo — o no hay tráfico de IA. 👍
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border/60 text-left text-xs text-muted-foreground">
                    <th className="pb-2 pr-3 font-medium">Servicio</th>
                    <th className="pb-2 pr-3 font-medium">Estado</th>
                    <th className="pb-2 pr-3 font-medium text-right">Equipos</th>
                    <th className="pb-2 pr-3 font-medium text-right">Conexiones</th>
                    <th className="pb-2 font-medium text-right">Política</th>
                  </tr>
                </thead>
                <tbody>
                  {ov.services.map((s) => (
                    <tr key={s.service} className="border-b border-border/30 last:border-0">
                      <td className="py-2.5 pr-3">
                        <div className="font-medium">{s.name}</div>
                        <div className="text-[10px] text-muted-foreground">{s.vendor}</div>
                      </td>
                      <td className="py-2.5 pr-3">
                        <Pill ok={s.sanctioned}>{s.sanctioned ? 'aprobado' : 'shadow'}</Pill>
                      </td>
                      <td className="py-2.5 pr-3 text-right">{s.devices}</td>
                      <td className="py-2.5 pr-3 text-right">{s.hits.toLocaleString('es-CO')}</td>
                      <td className="py-2.5 text-right">
                        {s.sanctioned ? (
                          <Button variant="ghost" size="sm" className="h-7 text-[11px]" disabled={busy === s.service}
                            onClick={() => togglePolicy(s.service, false)}>
                            <Ban className="mr-1 h-3.5 w-3.5" /> Marcar shadow
                          </Button>
                        ) : (
                          <Button variant="ghost" size="sm" className="h-7 text-[11px]" disabled={busy === s.service}
                            onClick={() => togglePolicy(s.service, true)}>
                            <Check className="mr-1 h-3.5 w-3.5" /> Aprobar
                          </Button>
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

      {/* Equipos */}
      {ov && ov.devices.length > 0 && (
        <Card>
          <CardHeader><CardTitle className="text-muted-foreground">Equipos ({ov.devices.length})</CardTitle></CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border/60 text-left text-xs text-muted-foreground">
                    <th className="pb-2 pr-3 font-medium">Equipo</th>
                    <th className="pb-2 pr-3 font-medium">Usuario</th>
                    <th className="pb-2 pr-3 font-medium text-right">Servicios</th>
                    <th className="pb-2 pr-3 font-medium text-right">Conexiones</th>
                    <th className="pb-2 pr-3 font-medium">Estado</th>
                    <th className="pb-2 font-medium text-right">Últ. visto</th>
                  </tr>
                </thead>
                <tbody>
                  {ov.devices.map((d) => (
                    <tr key={d.srcip} className="border-b border-border/30 last:border-0">
                      <td className="py-2.5 pr-3 font-mono text-[12px]">{d.host || d.srcip}{d.host && <div className="text-[10px] text-muted-foreground/70">{d.srcip}</div>}</td>
                      <td className="py-2.5 pr-3 text-[12px]">{d.srcuser || <span className="text-muted-foreground">—</span>}</td>
                      <td className="py-2.5 pr-3 text-right">{d.servicios}</td>
                      <td className="py-2.5 pr-3 text-right">{d.hits.toLocaleString('es-CO')}</td>
                      <td className="py-2.5 pr-3"><Pill ok={!d.shadow}>{d.shadow ? 'shadow' : 'ok'}</Pill></td>
                      <td className="py-2.5 text-right text-[11px] text-muted-foreground">{new Date(d.last_seen).toLocaleString('es-CO')}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      <p className="flex items-start gap-1.5 text-[11px] text-muted-foreground">
        <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0" />
        La detección es por red (SNI que reporta el firewall) — no requiere agente ni bloquea nada. Marca como
        <b> aprobado</b> los servicios que la organización permite; el resto se cuenta como <b>shadow AI</b> y se
        avisa por Telegram cuando aparece uno nuevo. Riesgo principal: fuga de información sensible hacia IA externa.
      </p>
    </div>
  );
}
