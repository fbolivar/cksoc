/**
 * Monitoreo de Exposición de Credenciales (Have I Been Pwned - Domain).
 * Detecta cuentas del dominio del cliente filtradas en brechas conocidas.
 */
import { useEffect, useState } from 'react';
import { AxiosError } from 'axios';
import {
  KeyRound, ShieldAlert, Search, RefreshCw, Loader2, Trash2, Plus,
  CheckCircle2, EyeOff, Globe, AlertTriangle, Database, ShieldCheck, ExternalLink,
} from 'lucide-react';
import { credExpApi, type CredSummary, type CredAccount, type HibpDiagnostics } from '@/lib/credexp';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';

// Panel de diagnóstico de prerequisitos (estado real de la cuenta HIBP, en vivo).
function DiagnosticsPanel({ d }: { d: HibpDiagnostics }) {
  const okColor = 'hsl(var(--success))';
  const Row = ({ ok, label, value }: { ok: boolean | null; label: string; value: string }) => (
    <div className="flex items-center gap-2 text-xs">
      {ok === true ? <CheckCircle2 className="h-4 w-4 shrink-0" style={{ color: okColor }} />
        : ok === false ? <AlertTriangle className="h-4 w-4 shrink-0" style={{ color: 'hsl(var(--destructive))' }} />
        : <div className="h-4 w-4 shrink-0" />}
      <span className="text-muted-foreground">{label}:</span> <span className="font-medium">{value}</span>
    </div>
  );
  return (
    <Card>
      <CardContent className="p-4">
        <div className="mb-3 flex items-center justify-between gap-2">
          <p className="flex items-center gap-2 text-sm font-semibold">
            {d.ready ? <ShieldCheck className="h-4 w-4" style={{ color: okColor }} /> : <AlertTriangle className="h-4 w-4" style={{ color: 'hsl(var(--warn-orange))' }} />}
            Diagnóstico de conexión con HIBP
          </p>
          <span className="hw-mono text-[10px] uppercase tracking-widest text-muted-foreground">prerequisitos</span>
        </div>

        <div className="grid gap-1.5 sm:grid-cols-2">
          <Row ok={d.keyConfigured} label="Clave HIBP" value={d.keyConfigured ? 'configurada' : 'ausente'} />
          <Row ok={d.keyValid} label="Clave válida" value={d.keyValid === null ? 'sin verificar' : d.keyValid ? 'sí' : 'rechazada'} />
          {d.plan && <Row ok label="Plan" value={`${d.plan.name} · ${d.plan.maxBreachedPerDomain}/dominio · vence ${d.plan.subscribedUntil.slice(0, 10)}`} />}
          <Row ok={d.ready} label="Listo para escanear" value={d.ready ? 'sí' : 'faltan pasos'} />
        </div>

        {/* Dominios monitoreados y su estado real en HIBP */}
        <div className="mt-3 space-y-1.5">
          {d.monitored.map((m) => (
            <div key={m.domain} className="flex flex-wrap items-center gap-2 rounded border border-border p-2 text-xs">
              {m.registeredInHibp ? <CheckCircle2 className="h-4 w-4 shrink-0" style={{ color: okColor }} /> : <AlertTriangle className="h-4 w-4 shrink-0" style={{ color: 'hsl(var(--warn-orange))' }} />}
              <span className="hw-mono font-medium">{m.domain}</span>
              <span className="text-muted-foreground">{m.registeredInHibp ? 'registrado y verificado en HIBP ✓' : 'no registrado en HIBP'}</span>
              {!m.registeredInHibp && m.ultimoError && <span className="w-full pl-6 text-[11px] text-muted-foreground/80">{m.ultimoError}</span>}
            </div>
          ))}
        </div>

        {/* Pasos accionables */}
        {d.steps.length > 0 && (
          <div className="mt-3">
            <p className="mb-1.5 text-[11px] font-medium text-muted-foreground">Para activar el escaneo (una sola vez):</p>
            <ol className="space-y-2">
              {d.steps.map((s, i) => (
                <li key={i} className="flex gap-2.5 rounded border border-border p-2.5">
                  <span className="hw-mono flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-secondary text-[11px] font-bold">{i + 1}</span>
                  <div><p className="text-xs font-semibold">{s.step}</p><p className="mt-0.5 text-[11px] text-muted-foreground">{s.detail}</p></div>
                </li>
              ))}
            </ol>
            <a href="https://haveibeenpwned.com/DomainSearch" target="_blank" rel="noopener noreferrer"
              className="mt-2 inline-flex items-center gap-1 text-[11px] text-primary hover:underline">
              Abrir el panel de HIBP Domain Search <ExternalLink className="h-3 w-3" />
            </a>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export default function CredentialExposure() {
  const [sum, setSum] = useState<CredSummary | null>(null);
  const [diag, setDiag] = useState<HibpDiagnostics | null>(null);
  const [accounts, setAccounts] = useState<CredAccount[]>([]);
  const [nuevoDom, setNuevoDom] = useState('');
  const [q, setQ] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  const flash = (kind: 'ok' | 'err', text: string) => {
    setMsg({ kind, text });
    setTimeout(() => setMsg(null), 5000);
  };
  const err = (e: unknown, fb: string) =>
    flash('err', (e as AxiosError<{ error?: string }>).response?.data?.error ?? fb);

  async function reload() {
    const [s, a] = await Promise.all([credExpApi.summary(), credExpApi.accounts({ q: q || undefined })]);
    setSum(s); setAccounts(a);
    credExpApi.diagnostics().then(setDiag).catch(() => setDiag(null)); // en vivo, no bloquea la vista
  }
  useEffect(() => { reload().catch(() => flash('err', 'No se pudo cargar')); /* eslint-disable-next-line */ }, []);

  async function buscar() {
    try { setAccounts(await credExpApi.accounts({ q: q || undefined })); } catch (e) { err(e, 'Error al buscar'); }
  }
  async function addDom() {
    if (!nuevoDom.trim()) return;
    setBusy('add');
    try { await credExpApi.addDomain(nuevoDom); setNuevoDom(''); await reload(); flash('ok', 'Dominio añadido'); }
    catch (e) { err(e, 'No se pudo añadir'); } finally { setBusy(null); }
  }
  async function delDom(d: string) {
    if (!confirm(`¿Dejar de vigilar ${d} y borrar sus cuentas expuestas?`)) return;
    try { await credExpApi.removeDomain(d); await reload(); flash('ok', 'Dominio eliminado'); }
    catch (e) { err(e, 'No se pudo eliminar'); }
  }
  async function scan(d?: string) {
    setBusy(d ?? 'scan-all');
    try {
      if (d) { const r = await credExpApi.scanDomain(d); flash('ok', `${d}: ${r.total} cuenta(s), ${r.nuevas} nueva(s)`); }
      else { const rs = await credExpApi.scanAll(); const n = rs.reduce((s, x) => s + x.nuevas, 0); flash('ok', `Escaneo completado · ${n} cuenta(s) nueva(s)`); }
      await reload();
    } catch (e) { err(e, 'Error en el escaneo'); } finally { setBusy(null); }
  }
  async function estado(a: CredAccount, e: 'ack' | 'dismissed' | 'open') {
    try { await credExpApi.setStatus(a.id, e); await reload(); } catch (x) { err(x, 'No se pudo actualizar'); }
  }

  const badgeEstado = (e: string) =>
    e === 'dismissed' ? <Badge variant="muted">descartada</Badge>
    : e === 'ack' ? <Badge variant="default">reconocida</Badge>
    : <Badge variant="warning">abierta</Badge>;

  return (
    <div className="mx-auto max-w-5xl space-y-5">
      <div>
        <h1 className="hw-mono flex items-center gap-2 text-2xl font-bold tracking-tight">
          <KeyRound className="h-6 w-6 text-primary" /> EXPOSICIÓN DE CREDENCIALES
        </h1>
        <p className="hw-mono text-[11px] tracking-wide text-muted-foreground">
          DOMINIO // BRECHAS CONOCIDAS // ALERTA TEMPRANA
        </p>
      </div>

      {msg && (
        <div className={`rounded-md border px-3 py-2 text-sm ${msg.kind === 'ok'
          ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200'
          : 'border-destructive/40 bg-destructive/10 text-destructive'}`}>{msg.text}</div>
      )}

      {/* Diagnóstico de prerequisitos en vivo (reemplaza el aviso estático). Se oculta cuando todo está listo. */}
      {diag && !diag.ready && <DiagnosticsPanel d={diag} />}

      {/* KPIs */}
      <div className="grid gap-3 sm:grid-cols-4">
        {[
          { icon: ShieldAlert, col: 'destructive', v: sum?.totalExpuestas ?? 0, l: 'Cuentas expuestas' },
          { icon: AlertTriangle, col: 'warn-orange', v: sum?.abiertas ?? 0, l: 'Sin revisar' },
          { icon: Database, col: 'primary', v: sum?.cuentasCriticas ?? 0, l: 'En 3+ brechas' },
          { icon: Globe, col: 'cyan', v: sum?.dominios.length ?? 0, l: 'Dominios vigilados' },
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

      {/* Dominios */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <CardTitle className="text-muted-foreground">Dominios vigilados</CardTitle>
          <Button size="sm" variant="outline" onClick={() => scan()} disabled={!!busy || (sum?.dominios.length ?? 0) === 0}>
            {busy === 'scan-all' ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />} Escanear todos
          </Button>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex flex-wrap items-end gap-2">
            <div className="flex-1 space-y-1" style={{ minWidth: 220 }}>
              <Label htmlFor="dom">Añadir dominio</Label>
              <Input id="dom" placeholder="ej. dga.com" value={nuevoDom}
                onChange={(e) => setNuevoDom(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && addDom()} />
            </div>
            <Button onClick={addDom} disabled={busy === 'add' || !nuevoDom.trim()}>
              {busy === 'add' ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />} Añadir
            </Button>
          </div>

          {(sum?.dominios.length ?? 0) === 0 ? (
            <p className="py-3 text-center text-sm text-muted-foreground">Aún no hay dominios en vigilancia.</p>
          ) : (
            <div className="space-y-2">
              {sum!.dominios.map((d) => (
                <div key={d.domain} className="flex flex-wrap items-center gap-3 rounded-md border border-border/50 bg-card/40 px-3 py-2">
                  <Globe className="h-4 w-4 text-muted-foreground" />
                  <span className="font-medium">{d.domain}</span>
                  {d.verificado ? <Badge variant="success">verificado</Badge> : <Badge variant="muted">sin verificar</Badge>}
                  <span className="text-xs text-muted-foreground">
                    {d.expuestas ?? 0} expuesta(s)
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

      {/* Top brechas */}
      {sum && sum.topBrechas.length > 0 && (
        <Card>
          <CardHeader><CardTitle className="text-muted-foreground">Brechas con más cuentas del dominio</CardTitle></CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {sum.topBrechas.map((b) => (
                <span key={b.name} className="rounded-md border border-border/50 bg-card/40 px-2.5 py-1 text-xs">
                  <b>{b.title ?? b.name}</b> <span className="text-muted-foreground">· {b.cuentas} cuenta(s)</span>
                </span>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Cuentas expuestas */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <CardTitle className="text-muted-foreground">Cuentas expuestas ({accounts.length})</CardTitle>
          <div className="flex items-center gap-2">
            <Input placeholder="Buscar usuario…" value={q} className="h-9 w-44"
              onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && buscar()} />
            <Button size="icon" variant="outline" onClick={buscar}><Search className="h-4 w-4" /></Button>
          </div>
        </CardHeader>
        <CardContent>
          {accounts.length === 0 ? (
            <p className="py-6 text-center text-sm text-muted-foreground">
              No hay cuentas expuestas registradas. Añade un dominio y ejecuta un escaneo.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border/60 text-left text-xs text-muted-foreground">
                    <th className="pb-2 pr-4 font-medium">Cuenta</th>
                    <th className="pb-2 pr-4 font-medium">Brechas</th>
                    <th className="pb-2 pr-4 font-medium">Nº</th>
                    <th className="pb-2 pr-4 font-medium">Estado</th>
                    <th className="pb-2 font-medium text-right">Acciones</th>
                  </tr>
                </thead>
                <tbody>
                  {accounts.map((a) => (
                    <tr key={a.id} className="border-b border-border/30 last:border-0">
                      <td className="py-2.5 pr-4 font-mono text-[13px]">{a.alias}@{a.domain}</td>
                      <td className="py-2.5 pr-4">
                        <div className="flex flex-wrap gap-1">
                          {a.brechas.slice(0, 5).map((b) => (
                            <span key={b} className="rounded bg-foreground/8 px-1.5 py-0.5 text-[11px]">{b}</span>
                          ))}
                          {a.brechas.length > 5 && <span className="text-[11px] text-muted-foreground">+{a.brechas.length - 5}</span>}
                        </div>
                      </td>
                      <td className="py-2.5 pr-4">
                        <span className={a.num_brechas >= 3 ? 'font-bold text-destructive' : ''}>{a.num_brechas}</span>
                      </td>
                      <td className="py-2.5 pr-4">{badgeEstado(a.estado)}</td>
                      <td className="py-2.5">
                        <div className="flex justify-end gap-1">
                          {a.estado !== 'ack' && (
                            <Button variant="ghost" size="icon" title="Reconocer" onClick={() => estado(a, 'ack')}>
                              <CheckCircle2 className="h-4 w-4" />
                            </Button>
                          )}
                          {a.estado !== 'dismissed' && (
                            <Button variant="ghost" size="icon" title="Descartar" onClick={() => estado(a, 'dismissed')}>
                              <EyeOff className="h-4 w-4" />
                            </Button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <p className="mt-3 text-[11px] text-muted-foreground">
            Una cuenta expuesta significa que apareció en una brecha conocida. <b>No implica</b> que la contraseña actual
            siga siendo válida, pero sí que esa cuenta debe forzar cambio de contraseña y activar doble factor.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
