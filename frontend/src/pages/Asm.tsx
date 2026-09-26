/**
 * ASM — Attack Surface Management externo.
 * Descubre y vigila lo que los dominios del cliente exponen a Internet:
 * subdominios (crt.sh), puertos abiertos, certificados TLS e IPs en IOCs.
 */
import { useEffect, useState } from 'react';
import { AxiosError } from 'axios';
import {
  ScanSearch, Globe, RefreshCw, Loader2, Trash2, Plus, ShieldAlert,
  AlertTriangle, Network, CheckCircle2, EyeOff, ServerCog,
} from 'lucide-react';
import { asmApi, type AsmOverview, type AsmDomain, type AsmFinding, type Sev } from '@/lib/asm';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

const SEVS: Sev[] = ['critica', 'alta', 'media', 'baja', 'info'];
const SEV_COLOR: Record<Sev, string> = {
  critica: 'destructive', alta: 'warn-orange', media: 'primary', baja: 'cyan', info: 'muted-foreground',
};
const SEV_LABEL: Record<Sev, string> = {
  critica: 'crítica', alta: 'alta', media: 'media', baja: 'baja', info: 'info',
};
const TIPO_LABEL: Record<string, string> = {
  open_port: 'Puerto abierto', tls_expired: 'Certificado vencido', tls_expiring: 'Certificado por vencer',
  tls_selfsigned: 'Certificado autofirmado', ioc_match: 'IP en IOC', private_dns: 'Fuga de DNS interno',
};

function SevPill({ sev }: { sev: Sev }) {
  const c = SEV_COLOR[sev];
  return (
    <span className="hw-mono inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide"
      style={{ background: `hsl(var(--${c}) / .16)`, color: `hsl(var(--${c}))` }}>
      {SEV_LABEL[sev]}
    </span>
  );
}

export default function Asm() {
  const [ov, setOv] = useState<AsmOverview | null>(null);
  const [domains, setDomains] = useState<AsmDomain[]>([]);
  const [findings, setFindings] = useState<AsmFinding[]>([]);
  const [filtro, setFiltro] = useState<Sev | 'todas'>('todas');
  const [nuevoDom, setNuevoDom] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  const flash = (kind: 'ok' | 'err', text: string) => { setMsg({ kind, text }); setTimeout(() => setMsg(null), 5000); };
  const err = (e: unknown, fb: string) => flash('err', (e as AxiosError<{ error?: string }>).response?.data?.error ?? fb);

  async function reload() {
    const [o, d, f] = await Promise.all([asmApi.overview(), asmApi.domains(), asmApi.findings({ estado: 'open' })]);
    setOv(o); setDomains(d); setFindings(f);
  }
  useEffect(() => { reload().catch(() => flash('err', 'No se pudo cargar')); /* eslint-disable-next-line */ }, []);

  async function addDom() {
    if (!nuevoDom.trim()) return;
    setBusy('add');
    try { await asmApi.addDomain(nuevoDom); setNuevoDom(''); await reload(); flash('ok', 'Dominio añadido a la vigilancia'); }
    catch (e) { err(e, 'No se pudo añadir'); } finally { setBusy(null); }
  }
  async function delDom(d: string) {
    if (!confirm(`¿Dejar de vigilar ${d} y borrar sus activos y hallazgos?`)) return;
    try { await asmApi.removeDomain(d); await reload(); flash('ok', 'Dominio eliminado'); }
    catch (e) { err(e, 'No se pudo eliminar'); }
  }
  async function scan(d?: string) {
    setBusy(d ?? 'scan-all');
    try {
      if (d) { const r = await asmApi.scanDomain(d); flash('ok', `${d}: ${r.hosts} host(s), ${r.openPorts} puerto(s), ${r.nuevos} hallazgo(s) nuevo(s)`); }
      else { const rs = await asmApi.scanAll(); const n = rs.reduce((s, x) => s + x.nuevos, 0); flash('ok', `Escaneo completado · ${n} hallazgo(s) nuevo(s)`); }
      await reload();
    } catch (e) { err(e, 'Error en el escaneo'); } finally { setBusy(null); }
  }
  async function cerrar(f: AsmFinding, estado: 'resolved' | 'dismissed') {
    try { await asmApi.setFindingStatus(f.id, estado); await reload(); }
    catch (e) { err(e, 'No se pudo actualizar'); }
  }

  const abiertos = ov ? SEVS.reduce((s, k) => s + (ov.hallazgos[k] ?? 0), 0) : 0;
  const visibles = filtro === 'todas' ? findings : findings.filter((f) => f.severidad === filtro);

  return (
    <div className="mx-auto max-w-5xl space-y-5">
      <div>
        <h1 className="hw-mono flex items-center gap-2 text-2xl font-bold tracking-tight">
          <ScanSearch className="h-6 w-6 text-primary" /> SUPERFICIE DE ATAQUE EXTERNA
        </h1>
        <p className="hw-mono text-[11px] tracking-wide text-muted-foreground">
          DESCUBRIMIENTO // PUERTOS EXPUESTOS // CERTIFICADOS // IOC
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
          { icon: Network, col: 'primary', v: ov?.hosts ?? 0, l: 'Hosts descubiertos' },
          { icon: Globe, col: 'cyan', v: ov?.ips ?? 0, l: 'IPs públicas' },
          { icon: ShieldAlert, col: 'destructive', v: ov?.hallazgos.critica ?? 0, l: 'Exposiciones críticas' },
          { icon: AlertTriangle, col: 'warn-orange', v: ov?.hallazgos.alta ?? 0, l: 'Exposiciones altas' },
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

      {/* Dominios vigilados */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <CardTitle className="text-muted-foreground">Dominios vigilados</CardTitle>
          <Button size="sm" variant="outline" onClick={() => scan()} disabled={!!busy || domains.length === 0}>
            {busy === 'scan-all' ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />} Escanear todos
          </Button>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex flex-wrap items-end gap-2">
            <div className="flex-1 space-y-1" style={{ minWidth: 220 }}>
              <Label htmlFor="dom">Añadir dominio (solo dominios propios / autorizados)</Label>
              <Input id="dom" placeholder="ej. col-law.com" value={nuevoDom}
                onChange={(e) => setNuevoDom(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && addDom()} />
            </div>
            <Button onClick={addDom} disabled={busy === 'add' || !nuevoDom.trim()}>
              {busy === 'add' ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />} Añadir
            </Button>
          </div>

          {domains.length === 0 ? (
            <p className="py-3 text-center text-sm text-muted-foreground">Aún no hay dominios en vigilancia.</p>
          ) : (
            <div className="space-y-2">
              {domains.map((d) => (
                <div key={d.domain} className="flex flex-wrap items-center gap-3 rounded-md border border-border/50 bg-card/40 px-3 py-2">
                  <Globe className="h-4 w-4 text-muted-foreground" />
                  <span className="font-medium">{d.domain}</span>
                  <span className="text-xs text-muted-foreground">
                    {d.activos} activo(s) · {d.hallazgos} hallazgo(s)
                    {d.ultimo_scan ? ` · último escaneo ${new Date(d.ultimo_scan).toLocaleString('es-CO')}` : ' · sin escanear'}
                  </span>
                  {d.ultimo_error && <span className="text-xs text-destructive">⚠ {d.ultimo_error}</span>}
                  <div className="ml-auto flex gap-1">
                    <Button variant="ghost" size="icon" title="Escanear" onClick={() => scan(d.domain)} disabled={!!busy}>
                      {busy === d.domain ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
                    </Button>
                    <Button variant="ghost" size="icon" title="Eliminar" onClick={() => delDom(d.domain)}>
                      <Trash2 className="h-4 w-4 text-red-400" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Hallazgos */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <CardTitle className="text-muted-foreground">Exposiciones detectadas ({abiertos})</CardTitle>
          <div className="flex flex-wrap items-center gap-1">
            {(['todas', ...SEVS] as const).map((s) => (
              <Button key={s} size="sm" variant={filtro === s ? 'default' : 'ghost'}
                className="h-7 px-2 text-[11px]" onClick={() => setFiltro(s)}>
                {s === 'todas' ? 'Todas' : SEV_LABEL[s as Sev]}
                {s !== 'todas' && ov ? ` (${ov.hallazgos[s as Sev] ?? 0})` : ''}
              </Button>
            ))}
          </div>
        </CardHeader>
        <CardContent>
          {visibles.length === 0 ? (
            <p className="py-6 text-center text-sm text-muted-foreground">
              {abiertos === 0
                ? 'Sin exposiciones abiertas. Añade un dominio y ejecuta un escaneo — o la superficie está limpia. 👍'
                : 'No hay hallazgos con ese filtro.'}
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border/60 text-left text-xs text-muted-foreground">
                    <th className="pb-2 pr-3 font-medium">Sev.</th>
                    <th className="pb-2 pr-3 font-medium">Tipo</th>
                    <th className="pb-2 pr-3 font-medium">Host</th>
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
                        {f.host}{f.puerto ? <span className="text-muted-foreground">:{f.puerto}</span> : null}
                        {f.ip && <div className="text-[10px] text-muted-foreground/70">{f.ip}</div>}
                      </td>
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
          <p className="mt-3 flex items-start gap-1.5 text-[11px] text-muted-foreground">
            <ServerCog className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            El escaneo es <b>activo</b> y se limita a los dominios propios/autorizados que agregues aquí. Corre solo cada
            día (04:30) y avisa por Telegram las exposiciones nuevas de riesgo alto/crítico.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
