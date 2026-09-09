/**
 * Remediación (winget + apt vía Velociraptor): actualiza endpoints Windows/Linux
 * desde la GUI. Guardrails visibles: escaneo dry-run (sólo lectura), aplicación
 * restringida a equipos piloto, confirmación explícita y auditoría. Sólo admin.
 * Windows: actualiza apps winget seleccionadas. Linux: aplica SOLO parches de
 * seguridad (nunca reinicia) y permite activar la automatización (unattended-upgrades).
 */
import { useCallback, useEffect, useState } from 'react';
import { AxiosError } from 'axios';
import {
  Wrench, DownloadCloud, Loader2, RefreshCw, CheckCircle2, AlertTriangle,
  ShieldCheck, PackageCheck, PlayCircle, FlaskConical, MonitorSmartphone, Terminal, RotateCcw,
} from 'lucide-react';
import {
  remediationApi, pollJob,
  type RemediationHost, type WingetPackage, type RemediationJob,
} from '@/lib/remediation';
import { useAuth } from '@/lib/auth';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

function errMsg(e: unknown, fallback: string): string {
  const ax = e as AxiosError<{ error?: string }>;
  return ax?.response?.data?.error || (e as Error)?.message || fallback;
}

type ApplyState = Record<string, { status: 'running' | 'done' | 'error'; msg?: string }>;
type LinuxResult = { status: 'running' | 'done' | 'error'; msg: string; reboot?: boolean };

export default function Remediacion() {
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';

  const [hosts, setHosts] = useState<RemediationHost[] | null>(null);
  const [pilotHosts, setPilotHosts] = useState<string[]>([]);
  const [selected, setSelected] = useState<string>('');
  const [loadingHosts, setLoadingHosts] = useState(true);
  const [hostErr, setHostErr] = useState<string | null>(null);

  const [scanning, setScanning] = useState(false);
  const [scanErr, setScanErr] = useState<string | null>(null);
  const [packages, setPackages] = useState<WingetPackage[] | null>(null);
  const [scannedHost, setScannedHost] = useState<string>('');
  const [scannedPlatform, setScannedPlatform] = useState<'windows' | 'linux'>('windows');
  const [scanNote, setScanNote] = useState<string>('');
  const [scanReboot, setScanReboot] = useState<boolean>(false);

  // Windows: selección por paquete.
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [applyState, setApplyState] = useState<ApplyState>({});
  const [applying, setApplying] = useState(false);
  // Linux: acción en bloque.
  const [linuxBusy, setLinuxBusy] = useState(false);
  const [linuxResult, setLinuxResult] = useState<LinuxResult | null>(null);

  const [history, setHistory] = useState<RemediationJob[]>([]);

  const selectedHost = hosts?.find((h) => h.host === selected) || null;
  const canApply = isAdmin && !!selectedHost?.isPilot;
  const securityCount = (packages || []).filter((p) => p.security).length;

  const loadHosts = useCallback(async () => {
    setLoadingHosts(true); setHostErr(null);
    try {
      const d = await remediationApi.hosts();
      setHosts(d.hosts); setPilotHosts(d.pilotHosts);
      setSelected((prev) => prev || d.hosts.find((h) => h.online && h.isPilot)?.host || d.hosts.find((h) => h.online)?.host || '');
    } catch (e) { setHostErr(errMsg(e, 'No se pudieron cargar los equipos.')); }
    finally { setLoadingHosts(false); }
  }, []);

  const loadHistory = useCallback(async () => {
    try { setHistory(await remediationApi.jobs()); } catch { /* silencioso */ }
  }, []);

  useEffect(() => { if (isAdmin) { void loadHosts(); void loadHistory(); } }, [isAdmin, loadHosts, loadHistory]);

  async function doScan() {
    if (!selected || !selectedHost) return;
    setScanning(true); setScanErr(null); setPackages(null); setChecked(new Set());
    setApplyState({}); setScanNote(''); setLinuxResult(null); setScanReboot(false);
    try {
      const job = await remediationApi.scan(selected);
      const done = await pollJob(job.id);
      setScannedHost(selected);
      setScannedPlatform(selectedHost.platform);
      if (done.status === 'error') { setScanErr(done.error || 'El escaneo falló.'); }
      else {
        const pkgs = done.packages || [];
        setPackages(pkgs);
        setScanReboot(!!done.reboot);
        if (pkgs.length === 0) setScanNote('Este equipo está al día: no hay actualizaciones pendientes.');
        else if (selectedHost.platform === 'linux' && pkgs.filter((p) => p.security).length === 0)
          setScanNote('Hay actualizaciones, pero ninguna es de seguridad.');
      }
    } catch (e) { setScanErr(errMsg(e, 'No se pudo escanear el equipo.')); }
    finally { setScanning(false); void loadHistory(); }
  }

  // ---- Windows (por paquete) ----
  function toggle(id: string) {
    setChecked((prev) => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; });
  }
  function toggleAll() {
    if (!packages) return;
    setChecked((prev) => prev.size === packages.length ? new Set() : new Set(packages.map((p) => p.id)));
  }
  async function doApplyWindows() {
    if (!canApply || !scannedHost || checked.size === 0) return;
    const ids = [...checked];
    const ok = window.confirm(
      `Vas a ACTUALIZAR ${ids.length} aplicación(es) en el equipo piloto ${scannedHost}:\n\n${ids.join('\n')}` +
      `\n\nSe instalará en modo silencioso como SYSTEM. Algunas apps pueden cerrarse/reiniciarse. ¿Continuar?`
    );
    if (!ok) return;
    setApplying(true);
    for (const id of ids) {
      setApplyState((s) => ({ ...s, [id]: { status: 'running' } }));
      try {
        const job = await remediationApi.apply(scannedHost, id);
        const done = await pollJob(job.id);
        setApplyState((s) => ({ ...s, [id]: done.status === 'done'
          ? { status: 'done', msg: 'Actualizado' }
          : { status: 'error', msg: done.error || `winget código ${done.exit_code ?? '?'}` } }));
      } catch (e) {
        setApplyState((s) => ({ ...s, [id]: { status: 'error', msg: errMsg(e, 'Falló la aplicación.') } }));
      }
    }
    setApplying(false); void loadHistory();
  }

  // ---- Linux (solo-seguridad / automatización) ----
  async function doApplyLinuxSecurity() {
    if (!canApply || !scannedHost) return;
    const ok = window.confirm(
      `Vas a aplicar SOLO parches de SEGURIDAD (${securityCount}) en ${scannedHost} (apt).\n\n` +
      `No se reinicia el equipo automáticamente. Si algún servicio requiere reinicio, se te avisará. ¿Continuar?`
    );
    if (!ok) return;
    setLinuxBusy(true); setLinuxResult({ status: 'running', msg: 'Aplicando parches de seguridad…' });
    try {
      const job = await remediationApi.applySecurity(scannedHost);
      const done = await pollJob(job.id);
      setLinuxResult(done.status === 'done'
        ? { status: 'done', msg: 'Parches de seguridad aplicados.', reboot: !!done.reboot }
        : { status: 'error', msg: done.error || `apt código ${done.exit_code ?? '?'}` });
    } catch (e) { setLinuxResult({ status: 'error', msg: errMsg(e, 'Falló la aplicación.') }); }
    finally { setLinuxBusy(false); void loadHistory(); }
  }
  async function doAutoEnable() {
    if (!canApply || !scannedHost) return;
    const ok = window.confirm(
      `Vas a ACTIVAR la automatización de parches de SEGURIDAD (unattended-upgrades) en ${scannedHost}.\n\n` +
      `Instala/configura unattended-upgrades en modo solo-seguridad y SIN reinicio automático. ¿Continuar?`
    );
    if (!ok) return;
    setLinuxBusy(true); setLinuxResult({ status: 'running', msg: 'Activando automatización…' });
    try {
      const job = await remediationApi.autoEnable(scannedHost);
      const done = await pollJob(job.id);
      setLinuxResult(done.status === 'done'
        ? { status: 'done', msg: 'Automatización activada (solo-seguridad, sin reinicio automático).' }
        : { status: 'error', msg: done.error || `apt código ${done.exit_code ?? '?'}` });
    } catch (e) { setLinuxResult({ status: 'error', msg: errMsg(e, 'Falló la activación.') }); }
    finally { setLinuxBusy(false); void loadHistory(); }
  }

  if (!isAdmin) {
    return (
      <div className="p-6">
        <Card><CardContent className="p-6 text-sm text-muted-foreground">
          La Remediación está disponible sólo para administradores.
        </CardContent></Card>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 max-w-6xl">
      <header className="space-y-1">
        <h1 className="flex items-center gap-2 text-2xl font-bold tracking-tight">
          <Wrench className="h-6 w-6 text-primary" /> Remediación
        </h1>
        <p className="text-sm text-muted-foreground">
          Actualiza endpoints Windows (winget) y Linux (apt, solo-seguridad) vía Velociraptor. El escaneo
          es de sólo lectura; la aplicación queda auditada y restringida a los equipos piloto.
        </p>
      </header>

      <div className="flex items-start gap-3 rounded-xl border border-amber-300/60 bg-amber-50 p-4 text-sm dark:border-amber-500/30 dark:bg-amber-500/10">
        <FlaskConical className="mt-0.5 h-5 w-5 shrink-0 text-amber-600" />
        <div className="space-y-0.5">
          <p className="font-semibold text-amber-800 dark:text-amber-300">Modo piloto</p>
          <p className="text-amber-700/90 dark:text-amber-200/80">
            El <b>escaneo (dry-run)</b> funciona en cualquier equipo en línea, sin instalar nada. La
            <b> aplicación</b> sólo está habilitada en: <b>{pilotHosts.length ? pilotHosts.join(', ') : '(ninguno)'}</b>.
            En Linux se aplican <b>solo parches de seguridad</b> y nunca se reinicia automáticamente.
          </p>
        </div>
      </div>

      <Card>
        <CardContent className="p-5 space-y-4">
          <div className="flex flex-wrap items-end gap-3">
            <div className="flex-1 min-w-[260px] space-y-1">
              <label className="hw-mono text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">Equipo</label>
              <select
                value={selected}
                onChange={(e) => setSelected(e.target.value)}
                disabled={loadingHosts || scanning}
                className="w-full rounded-lg border border-border bg-background px-3 py-2 text-sm"
              >
                {!hosts?.length && <option value="">Sin equipos</option>}
                {hosts?.map((h) => (
                  <option key={h.host} value={h.host} disabled={!h.online}>
                    {h.host} · {h.platform === 'linux' ? 'Linux' : 'Windows'}{h.isPilot ? ' · PILOTO' : ''} — {h.online ? 'en línea' : `desconectado${h.lastSeenH != null ? ` (${h.lastSeenH} h)` : ''}`}
                  </option>
                ))}
              </select>
            </div>
            <Button onClick={doScan} disabled={!selected || scanning || !selectedHost?.online}>
              {scanning ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <DownloadCloud className="mr-2 h-4 w-4" />}
              Escanear (dry-run)
            </Button>
            <Button variant="outline" onClick={() => { void loadHosts(); }} disabled={loadingHosts || scanning}>
              <RefreshCw className={`mr-2 h-4 w-4 ${loadingHosts ? 'animate-spin' : ''}`} /> Equipos
            </Button>
          </div>

          {hostErr && <p className="text-sm text-red-600">{hostErr}</p>}
          {selectedHost && (
            <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
              {selectedHost.platform === 'linux' ? <Terminal className="h-3.5 w-3.5" /> : <MonitorSmartphone className="h-3.5 w-3.5" />}
              {selectedHost.os || selectedHost.platform} · {selectedHost.online ? 'agente en línea' : 'agente desconectado'}
              {selectedHost.isPilot ? ' · piloto (aplicación habilitada)' : ' · sólo lectura (no piloto)'}
            </p>
          )}
          {scanning && (
            <p className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" /> Escaneando {selected}… puede tardar 1–2 min.
            </p>
          )}
          {scanErr && <p className="flex items-center gap-2 text-sm text-red-600"><AlertTriangle className="h-4 w-4" /> {scanErr}</p>}
        </CardContent>
      </Card>

      {packages && (
        <Card>
          <CardContent className="p-5 space-y-4">
            <div className="flex items-center justify-between gap-3">
              <h2 className="flex items-center gap-2 text-base font-semibold">
                <PackageCheck className="h-5 w-5 text-primary" />
                Actualizaciones en {scannedHost}
                <span className="rounded-full bg-secondary px-2 py-0.5 text-xs font-medium text-muted-foreground">
                  {scannedPlatform === 'linux' ? `${securityCount} seg · ${packages.length} total` : packages.length}
                </span>
              </h2>
              {scannedPlatform === 'windows' && canApply && packages.length > 0 && (
                <Button onClick={doApplyWindows} disabled={applying || checked.size === 0}>
                  {applying ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <PlayCircle className="mr-2 h-4 w-4" />}
                  Aplicar {checked.size > 0 ? `(${checked.size})` : ''}
                </Button>
              )}
            </div>

            {scanNote && (
              <p className="flex items-center gap-2 rounded-lg bg-emerald-50 px-3 py-2 text-sm text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-300">
                <CheckCircle2 className="h-4 w-4" /> {scanNote}
              </p>
            )}
            {scanReboot && (
              <p className="flex items-center gap-2 rounded-lg bg-amber-50 px-3 py-2 text-sm text-amber-700 dark:bg-amber-500/10 dark:text-amber-300">
                <RotateCcw className="h-4 w-4" /> El equipo tiene un <b>reinicio pendiente</b> por actualizaciones previas.
              </p>
            )}
            {!canApply && packages.length > 0 && (
              <p className="flex items-center gap-2 rounded-lg bg-secondary px-3 py-2 text-xs text-muted-foreground">
                <ShieldCheck className="h-4 w-4" /> Este equipo no es piloto: se muestran las actualizaciones pero la aplicación está deshabilitada.
              </p>
            )}

            {/* Acciones Linux */}
            {scannedPlatform === 'linux' && canApply && (
              <div className="flex flex-wrap items-center gap-3">
                <Button onClick={doApplyLinuxSecurity} disabled={linuxBusy || securityCount === 0}>
                  {linuxBusy ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <ShieldCheck className="mr-2 h-4 w-4" />}
                  Aplicar solo seguridad ({securityCount})
                </Button>
                <Button variant="outline" onClick={doAutoEnable} disabled={linuxBusy}>
                  <PlayCircle className="mr-2 h-4 w-4" /> Activar automatización (unattended-upgrades)
                </Button>
              </div>
            )}
            {linuxResult && (
              <p className={`flex items-center gap-2 text-sm ${linuxResult.status === 'error' ? 'text-red-600' : linuxResult.status === 'done' ? 'text-emerald-600' : 'text-amber-600'}`}>
                {linuxResult.status === 'running' && <Loader2 className="h-4 w-4 animate-spin" />}
                {linuxResult.status === 'done' && <CheckCircle2 className="h-4 w-4" />}
                {linuxResult.status === 'error' && <AlertTriangle className="h-4 w-4" />}
                {linuxResult.msg}{linuxResult.reboot ? ' — requiere reinicio (no automático).' : ''}
              </p>
            )}

            {/* Tabla */}
            {packages.length > 0 && (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted-foreground">
                      {scannedPlatform === 'windows' && canApply && (
                        <th className="px-2 py-2 w-8">
                          <input type="checkbox" checked={checked.size === packages.length && packages.length > 0} onChange={toggleAll} />
                        </th>
                      )}
                      <th className="px-2 py-2">{scannedPlatform === 'linux' ? 'Paquete' : 'Aplicación'}</th>
                      {scannedPlatform === 'windows' && <th className="px-2 py-2">Id</th>}
                      {scannedPlatform === 'windows' && <th className="px-2 py-2">Instalada</th>}
                      <th className="px-2 py-2">Disponible</th>
                      {scannedPlatform === 'linux' && <th className="px-2 py-2">Tipo</th>}
                      {scannedPlatform === 'windows' && canApply && <th className="px-2 py-2">Estado</th>}
                    </tr>
                  </thead>
                  <tbody>
                    {packages.map((p) => {
                      const st = applyState[p.id];
                      return (
                        <tr key={p.id} className="border-b border-border/60">
                          {scannedPlatform === 'windows' && canApply && (
                            <td className="px-2 py-2">
                              <input type="checkbox" checked={checked.has(p.id)} onChange={() => toggle(p.id)} disabled={applying || st?.status === 'done'} />
                            </td>
                          )}
                          <td className="px-2 py-2 font-medium">{p.name}</td>
                          {scannedPlatform === 'windows' && <td className="px-2 py-2 hw-mono text-xs text-muted-foreground">{p.id}</td>}
                          {scannedPlatform === 'windows' && <td className="px-2 py-2 text-muted-foreground">{p.current}</td>}
                          <td className="px-2 py-2 font-semibold text-emerald-600 dark:text-emerald-400">{p.available}</td>
                          {scannedPlatform === 'linux' && (
                            <td className="px-2 py-2">
                              {p.security
                                ? <span className="rounded-full bg-red-100 px-2 py-0.5 text-xs font-medium text-red-700 dark:bg-red-500/15 dark:text-red-300">seguridad</span>
                                : <span className="text-xs text-muted-foreground">normal</span>}
                            </td>
                          )}
                          {scannedPlatform === 'windows' && canApply && (
                            <td className="px-2 py-2">
                              {st?.status === 'running' && <span className="flex items-center gap-1 text-amber-600"><Loader2 className="h-3.5 w-3.5 animate-spin" /> aplicando…</span>}
                              {st?.status === 'done' && <span className="flex items-center gap-1 text-emerald-600"><CheckCircle2 className="h-3.5 w-3.5" /> {st.msg}</span>}
                              {st?.status === 'error' && <span className="flex items-center gap-1 text-red-600"><AlertTriangle className="h-3.5 w-3.5" /> {st.msg}</span>}
                            </td>
                          )}
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      <Card>
        <CardContent className="p-5 space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-semibold">Historial reciente</h2>
            <Button variant="outline" size="sm" onClick={() => { void loadHistory(); }}><RefreshCw className="mr-2 h-3.5 w-3.5" /> Actualizar</Button>
          </div>
          {history.length === 0 ? (
            <p className="text-sm text-muted-foreground">Aún no hay acciones registradas.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted-foreground">
                    <th className="px-2 py-2">Cuándo</th>
                    <th className="px-2 py-2">Equipo</th>
                    <th className="px-2 py-2">SO</th>
                    <th className="px-2 py-2">Acción</th>
                    <th className="px-2 py-2">Detalle</th>
                    <th className="px-2 py-2">Estado</th>
                    <th className="px-2 py-2">Por</th>
                  </tr>
                </thead>
                <tbody>
                  {history.map((j) => (
                    <tr key={j.id} className="border-b border-border/60">
                      <td className="px-2 py-2 text-muted-foreground whitespace-nowrap">{new Date(j.created_at).toLocaleString('es-CO')}</td>
                      <td className="px-2 py-2 font-medium">{j.host}</td>
                      <td className="px-2 py-2 text-xs text-muted-foreground">{j.platform === 'linux' ? 'Linux' : 'Windows'}</td>
                      <td className="px-2 py-2">{j.kind === 'scan' ? 'Escaneo' : j.kind === 'auto' ? 'Automatización' : 'Aplicación'}</td>
                      <td className="px-2 py-2 hw-mono text-xs text-muted-foreground">
                        {j.kind === 'scan'
                          ? (Array.isArray(j.packages) ? `${j.packages.length} updates` : '—')
                          : (j.package || '—')}
                        {j.reboot ? ' · reinicio pend.' : ''}
                      </td>
                      <td className="px-2 py-2">
                        {j.status === 'running' && <span className="text-amber-600">en curso</span>}
                        {j.status === 'done' && <span className="text-emerald-600">ok</span>}
                        {j.status === 'error' && <span className="text-red-600" title={j.error || ''}>error</span>}
                      </td>
                      <td className="px-2 py-2 text-muted-foreground">{j.actor_email || '—'}</td>
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
