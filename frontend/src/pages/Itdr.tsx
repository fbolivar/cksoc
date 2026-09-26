/**
 * ITDR avanzado — amenazas de identidad sobre los logins de Microsoft 365:
 * viaje imposible y MFA-fatigue (bombing). Visibilidad + alerta.
 */
import { useEffect, useState } from 'react';
import { AxiosError } from 'axios';
import {
  Fingerprint, RefreshCw, Loader2, ShieldAlert, Plane, BellRing, CheckCircle2, EyeOff,
} from 'lucide-react';
import { itdrApi, type ItdrOverview, type ItdrFinding, type ItdrSev } from '@/lib/itdr';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

const SEV_COLOR: Record<ItdrSev, string> = { critica: 'destructive', alta: 'warn-orange', media: 'primary' };
const TIPO_LABEL: Record<string, string> = { impossible_travel: 'Viaje imposible', mfa_fatigue: 'MFA-fatigue' };

function SevPill({ sev }: { sev: ItdrSev }) {
  const c = SEV_COLOR[sev];
  return (
    <span className="hw-mono inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide"
      style={{ background: `hsl(var(--${c}) / .16)`, color: `hsl(var(--${c}))` }}>{sev}</span>
  );
}

export default function Itdr() {
  const [ov, setOv] = useState<ItdrOverview | null>(null);
  const [filtro, setFiltro] = useState<'todas' | 'impossible_travel' | 'mfa_fatigue'>('todas');
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  const flash = (kind: 'ok' | 'err', text: string) => { setMsg({ kind, text }); setTimeout(() => setMsg(null), 5000); };
  const err = (e: unknown, fb: string) => flash('err', (e as AxiosError<{ error?: string }>).response?.data?.error ?? fb);

  async function reload() { setOv(await itdrApi.overview()); }
  useEffect(() => { reload().catch(() => flash('err', 'No se pudo cargar')); /* eslint-disable-next-line */ }, []);

  async function scan() {
    setBusy('scan');
    try { const r = await itdrApi.scan('24h'); flash('ok', `Análisis completado · ${r.viajeImposible} viaje(s), ${r.mfaFatigue} MFA-fatigue, ${r.nuevos} nuevo(s)`); await reload(); }
    catch (e) { err(e, 'Error en el análisis'); } finally { setBusy(null); }
  }
  async function cerrar(f: ItdrFinding, estado: 'resolved' | 'dismissed') {
    try { await itdrApi.setStatus(f.id, estado); await reload(); } catch (e) { err(e, 'No se pudo actualizar'); }
  }

  const s = ov?.severidad;
  const findings = ov?.top ?? [];
  const visibles = filtro === 'todas' ? findings : findings.filter((f) => f.tipo === filtro);

  return (
    <div className="mx-auto max-w-5xl space-y-5">
      <div>
        <h1 className="hw-mono flex items-center gap-2 text-2xl font-bold tracking-tight">
          <Fingerprint className="h-6 w-6 text-primary" /> ITDR · AMENAZAS DE IDENTIDAD
        </h1>
        <p className="hw-mono text-[11px] tracking-wide text-muted-foreground">
          MICROSOFT 365 // VIAJE IMPOSIBLE // MFA-FATIGUE
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
          { icon: ShieldAlert, col: 'destructive', v: s?.critica ?? 0, l: 'Críticas' },
          { icon: ShieldAlert, col: 'warn-orange', v: s?.alta ?? 0, l: 'Altas' },
          { icon: Plane, col: 'cyan', v: ov?.tipo.impossible_travel ?? 0, l: 'Viaje imposible' },
          { icon: BellRing, col: 'primary', v: ov?.tipo.mfa_fatigue ?? 0, l: 'MFA-fatigue' },
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
          <CardTitle className="text-muted-foreground">Amenazas de identidad ({findings.length})</CardTitle>
          <div className="flex flex-wrap items-center gap-1">
            {(['todas', 'impossible_travel', 'mfa_fatigue'] as const).map((t) => (
              <Button key={t} size="sm" variant={filtro === t ? 'default' : 'ghost'} className="h-7 px-2 text-[11px]" onClick={() => setFiltro(t)}>
                {t === 'todas' ? 'Todas' : TIPO_LABEL[t]}
              </Button>
            ))}
            <Button size="sm" variant="outline" className="h-7" onClick={scan} disabled={!!busy}>
              {busy === 'scan' ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />} Analizar
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {visibles.length === 0 ? (
            <p className="py-6 text-center text-sm text-muted-foreground">
              Sin amenazas de identidad abiertas. Ejecuta un análisis — o los inicios de sesión están limpios. 👍
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border/60 text-left text-xs text-muted-foreground">
                    <th className="pb-2 pr-3 font-medium">Sev.</th>
                    <th className="pb-2 pr-3 font-medium">Tipo</th>
                    <th className="pb-2 pr-3 font-medium">Usuario</th>
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
            <b>Viaje imposible</b>: dos accesos exitosos desde ubicaciones incompatibles con el tiempo transcurrido
            (excluye la VPN/relay corporativa para evitar falsos positivos). <b>MFA-fatigue</b>: ráfaga de rechazos de
            MFA — el atacante ya tiene la contraseña y bombardea el segundo factor. Si terminó en un acceso exitoso,
            se marca <b>crítica</b> (posible cuenta cedida): forzar cambio de contraseña + revocar sesiones.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
