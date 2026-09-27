/**
 * DRP — Riesgo digital (Digital Risk Protection): dominios que suplantan la
 * marca (typosquatting + certificate transparency) + credenciales expuestas.
 */
import { useEffect, useState } from 'react';
import { AxiosError } from 'axios';
import { Eye, RefreshCw, Loader2, Globe, Mail, Award, KeyRound, CheckCircle2, EyeOff } from 'lucide-react';
import { drpApi, type DrpOverview, type DrpFinding, type DrpSev } from '@/lib/drp';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

const SEV_COLOR: Record<DrpSev, string> = { critica: 'destructive', alta: 'warn-orange', media: 'primary' };
const TIPOS = ['lookalike_domain', 'lookalike_cert'] as const;
const TIPO_LABEL: Record<string, string> = { lookalike_domain: 'Dominio parecido', lookalike_cert: 'Certificado lookalike' };

function SevPill({ sev }: { sev: DrpSev }) {
  const c = SEV_COLOR[sev];
  return <span className="hw-mono inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide"
    style={{ background: `hsl(var(--${c}) / .16)`, color: `hsl(var(--${c}))` }}>{sev}</span>;
}

export default function Drp() {
  const [ov, setOv] = useState<DrpOverview | null>(null);
  const [filtro, setFiltro] = useState<'todas' | (typeof TIPOS)[number]>('todas');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  const flash = (kind: 'ok' | 'err', text: string) => { setMsg({ kind, text }); setTimeout(() => setMsg(null), 6000); };
  const err = (e: unknown, fb: string) => flash('err', (e as AxiosError<{ error?: string }>).response?.data?.error ?? fb);

  async function reload() { setOv(await drpApi.overview()); }
  useEffect(() => { reload().catch(() => flash('err', 'No se pudo cargar')); /* eslint-disable-next-line */ }, []);

  async function scan() {
    setBusy(true);
    try { const r = await drpApi.scan(); flash('ok', `Barrido completado · ${r.generados} generados, ${r.registrados} activos, ${r.certs} con certificado, ${r.nuevos} nuevo(s)`); await reload(); }
    catch (e) { err(e, 'Error en el barrido'); } finally { setBusy(false); }
  }
  async function cerrar(f: DrpFinding, estado: 'resolved' | 'dismissed') {
    try { await drpApi.setStatus(f.id, estado); await reload(); } catch (e) { err(e, 'No se pudo actualizar'); }
  }

  const t = ov?.tipo ?? {};
  const findings = ov?.top ?? [];
  const visibles = filtro === 'todas' ? findings : findings.filter((f) => f.tipo === filtro);

  return (
    <div className="mx-auto max-w-5xl space-y-5">
      <div>
        <h1 className="hw-mono flex items-center gap-2 text-2xl font-bold tracking-tight">
          <Eye className="h-6 w-6 text-primary" /> RIESGO DIGITAL · DRP
        </h1>
        <p className="hw-mono text-[11px] tracking-wide text-muted-foreground">
          TYPOSQUATTING // CERTIFICATE TRANSPARENCY // CREDENCIALES FILTRADAS
        </p>
      </div>

      {msg && (
        <div className={`rounded-md border px-3 py-2 text-sm ${msg.kind === 'ok'
          ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200'
          : 'border-destructive/40 bg-destructive/10 text-destructive'}`}>{msg.text}</div>
      )}

      <div className="grid gap-3 sm:grid-cols-4">
        {[
          { icon: Globe, col: 'warn-orange', v: t.lookalike_domain ?? 0, l: 'Dominios parecidos activos' },
          { icon: Mail, col: 'destructive', v: ov?.conMx ?? 0, l: 'Con MX (pueden suplantar correo)' },
          { icon: Award, col: 'cyan', v: t.lookalike_cert ?? 0, l: 'Con certificado (crt.sh)' },
          { icon: KeyRound, col: 'primary', v: ov?.credencialesExpuestas ?? 0, l: 'Credenciales expuestas' },
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
          <CardTitle className="text-muted-foreground">Dominios que suplantan la marca ({findings.length})</CardTitle>
          <div className="flex flex-wrap items-center gap-1">
            {(['todas', ...TIPOS] as const).map((x) => (
              <Button key={x} size="sm" variant={filtro === x ? 'default' : 'ghost'} className="h-7 px-2 text-[11px]" onClick={() => setFiltro(x)}>
                {x === 'todas' ? 'Todos' : TIPO_LABEL[x]}
              </Button>
            ))}
            <Button size="sm" variant="outline" className="h-7" onClick={scan} disabled={busy}>
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />} Barrer
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {visibles.length === 0 ? (
            <p className="py-6 text-center text-sm text-muted-foreground">
              Sin dominios parecidos activos. Ejecuta un barrido — o la marca no tiene suplantadores registrados. 👍
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border/60 text-left text-xs text-muted-foreground">
                    <th className="pb-2 pr-3 font-medium">Sev.</th>
                    <th className="pb-2 pr-3 font-medium">Tipo</th>
                    <th className="pb-2 pr-3 font-medium">Dominio</th>
                    <th className="pb-2 pr-3 font-medium">Detalle</th>
                    <th className="pb-2 font-medium text-right">Acciones</th>
                  </tr>
                </thead>
                <tbody>
                  {visibles.map((f) => (
                    <tr key={f.id} className="border-b border-border/30 last:border-0 align-top">
                      <td className="py-2.5 pr-3"><SevPill sev={f.severidad} /></td>
                      <td className="py-2.5 pr-3 text-xs text-muted-foreground whitespace-nowrap">{TIPO_LABEL[f.tipo] ?? f.tipo}</td>
                      <td className="py-2.5 pr-3 font-mono text-[12px]">
                        <a href={`https://www.virustotal.com/gui/domain/${f.dominio}`} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">{f.dominio}</a>
                        {Boolean((f.meta as { mx?: boolean }).mx) && <span className="ml-1 rounded bg-destructive/15 px-1 text-[9px] text-destructive">MX</span>}
                      </td>
                      <td className="py-2.5 pr-3 text-[13px]">{f.detalle}</td>
                      <td className="py-2.5">
                        <div className="flex justify-end gap-1">
                          <Button variant="ghost" size="icon" title="Marcar resuelto (takedown/benigno)" onClick={() => cerrar(f, 'resolved')}><CheckCircle2 className="h-4 w-4" /></Button>
                          <Button variant="ghost" size="icon" title="Descartar (propio/no relevante)" onClick={() => cerrar(f, 'dismissed')}><EyeOff className="h-4 w-4" /></Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <p className="mt-3 text-[11px] text-muted-foreground">
            Sin credenciales del cliente: se generan variantes del dominio y se detectan las <b>registradas y activas</b>
            (DNS + MX = pueden enviar correo suplantando) y las que ya sacaron <b>certificado</b>. Acciones ante un
            positivo: reportar para <b>takedown</b> al registrador/hosting, avisar a los usuarios y vigilar correos que lo
            referencien. El clic en el dominio abre VirusTotal.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
