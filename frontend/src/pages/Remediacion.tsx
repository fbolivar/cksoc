/**
 * Remediación (MVP winget): actualiza Windows/apps en un endpoint desde la GUI,
 * vía Velociraptor. Guardrails visibles: escaneo dry-run (sólo lectura), aplicación
 * restringida a equipos piloto, confirmación explícita y auditoría. Sólo admin.
 */
import { useCallback, useEffect, useState } from 'react';
import { AxiosError } from 'axios';
import {
  Wrench, DownloadCloud, Loader2, RefreshCw, CheckCircle2, AlertTriangle,
  ShieldCheck, PackageCheck, PlayCircle, FlaskConical,
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
  const [scanNote, setScanNote] = useState<string>('');

  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [applyState, setApplyState] = useState<ApplyState>({});
  const [applying, setApplying] = useState(false);

  const [history, setHistory] = useState<RemediationJob[]>([]);

  const selectedHost = hosts?.find((h) => h.host === selected) || null;
  const canApply = isAdmin && !!selectedHost?.isPilot;

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
    if (!selected) return;
    setScanning(true); setScanErr(null); setPackages(null); setChecked(new Set()); setApplyState({}); setScanNote('');
    try {
      const job = await remediationApi.scan(selected);
      const done = await pollJob(job.id);
      setScannedHost(selected);
      if (done.status === 'error') { setScanErr(done.error || 'El escaneo falló.'); }
      else {
        const pkgs = done.packages || [];
        setPackages(pkgs);
        if (pkgs.length === 0) setScanNote('Este equipo está al día: winget no reporta actualizaciones pendientes.');
      }
    } catch (e) { setScanErr(errMsg(e, 'No se pudo escanear el equipo.')); }
    finally { setScanning(false); void loadHistory(); }
  }

  function toggle(id: string) {
    setChecked((prev) => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; });
  }
  function toggleAll() {
    if (!packages) return;
    setChecked((prev) => prev.size === packages.length ? new Set() : new Set(packages.map((p) => p.id)));
  }

  async function doApply() {
    if (!canApply || !scannedHost || checked.size === 0) return;
    const ids = [...checked];
    const ok = window.confirm(
      `Vas a ACTUALIZAR ${ids.length} aplicación(es) en el equipo piloto ${scannedHost}:\n\n` +
      ids.join('\n') +
      `\n\nSe instalará en modo silencioso como SYSTEM. Algunas apps pueden cerrarse/reiniciarse. ¿Continuar?`
    );
    if (!ok) return;
    setApplying(true);
    for (const id of ids) {
      setApplyState((s) => ({ ...s, [id]: { status: 'running' } }));
      try {
        const job = await remediationApi.apply(scannedHost, id);
        const done = await pollJob(job.id);
        setApplyState((s) => ({
          ...s,
          [id]: done.status === 'done'
            ? { status: 'done', msg: 'Actualizado' }
            : { status: 'error', msg: done.error || `winget código ${done.exit_code ?? '?'}` },
        }));
      } catch (e) {
        setApplyState((s) => ({ ...s, [id]: { status: 'error', msg: errMsg(e, 'Falló la aplicación.') } }));
      }
    }
    setApplying(false);
    void loadHistory();
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
          Actualiza Windows y aplicaciones (winget) en los endpoints, vía Velociraptor. El escaneo es de
          sólo lectura; la aplicación queda auditada y, por ahora, restringida a los equipos piloto.
        </p>
      </header>

      {/* Banner de alcance / piloto */}
      <div className="flex items-start gap-3 rounded-xl border border-amber-300/60 bg-amber-50 p-4 text-sm dark:border-amber-500/30 dark:bg-amber-500/10">
        <FlaskConical className="mt-0.5 h-5 w-5 shrink-0 text-amber-600" />
        <div className="space-y-0.5">
          <p className="font-semibold text-amber-800 dark:text-amber-300">Modo piloto</p>
          <p className="text-amber-700/90 dark:text-amber-200/80">
            El <b>escaneo (dry-run)</b> funciona en cualquier equipo Windows en línea, sin instalar nada.
            La <b>aplicación de actualizaciones</b> sólo está habilitada en:{' '}
            <b>{pilotHosts.length ? pilotHosts.join(', ') : '(ninguno configurado)'}</b>.
          </p>
        </div>
      </div>

      {/* Selección de equipo + escaneo */}
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
                    {h.host}{h.isPilot ? ' · PILOTO' : ''} — {h.online ? 'en línea' : `desconectado${h.lastSeenH != null ? ` (${h.lastSeenH} h)` : ''}`}
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
            <p className="text-xs text-muted-foreground">
              {selectedHost.os || 'Windows'} · {selectedHost.online ? 'agente en línea' : 'agente desconectado'}
              {selectedHost.isPilot ? ' · equipo piloto (aplicación habilitada)' : ' · sólo lectura (no piloto)'}
            </p>
          )}
          {scanning && (
            <p className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" /> Escaneando {selected}… winget puede tardar 1–2 min en la primera consulta.
            </p>
          )}
          {scanErr && (
            <p className="flex items-center gap-2 text-sm text-red-600"><AlertTriangle className="h-4 w-4" /> {scanErr}</p>
          )}
        </CardContent>
      </Card>

      {/* Resultados del escaneo */}
      {packages && (
        <Card>
          <CardContent className="p-5 space-y-4">
            <div className="flex items-center justify-between gap-3">
              <h2 className="flex items-center gap-2 text-base font-semibold">
                <PackageCheck className="h-5 w-5 text-primary" />
                Actualizaciones en {scannedHost}
                <span className="rounded-full bg-secondary px-2 py-0.5 text-xs font-medium text-muted-foreground">{packages.length}</span>
              </h2>
              {canApply && packages.length > 0 && (
                <Button onClick={doApply} disabled={applying || checked.size === 0}>
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

            {!canApply && packages.length > 0 && (
              <p className="flex items-center gap-2 rounded-lg bg-secondary px-3 py-2 text-xs text-muted-foreground">
                <ShieldCheck className="h-4 w-4" /> Este equipo no es piloto: se muestran las actualizaciones pero la aplicación está deshabilitada.
              </p>
            )}

            {packages.length > 0 && (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted-foreground">
                      {canApply && (
                        <th className="px-2 py-2 w-8">
                          <input type="checkbox" checked={checked.size === packages.length && packages.length > 0} onChange={toggleAll} />
                        </th>
                      )}
                      <th className="px-2 py-2">Aplicación</th>
                      <th className="px-2 py-2">Id</th>
                      <th className="px-2 py-2">Instalada</th>
                      <th className="px-2 py-2">Disponible</th>
                      {canApply && <th className="px-2 py-2">Estado</th>}
                    </tr>
                  </thead>
                  <tbody>
                    {packages.map((p) => {
                      const st = applyState[p.id];
                      return (
                        <tr key={p.id} className="border-b border-border/60">
                          {canApply && (
                            <td className="px-2 py-2">
                              <input type="checkbox" checked={checked.has(p.id)} onChange={() => toggle(p.id)} disabled={applying || st?.status === 'done'} />
                            </td>
                          )}
                          <td className="px-2 py-2 font-medium">{p.name}</td>
                          <td className="px-2 py-2 hw-mono text-xs text-muted-foreground">{p.id}</td>
                          <td className="px-2 py-2 text-muted-foreground">{p.current}</td>
                          <td className="px-2 py-2 font-semibold text-emerald-600 dark:text-emerald-400">{p.available}</td>
                          {canApply && (
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

      {/* Historial / auditoría */}
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
                    <th className="px-2 py-2">Acción</th>
                    <th className="px-2 py-2">Paquete</th>
                    <th className="px-2 py-2">Estado</th>
                    <th className="px-2 py-2">Por</th>
                  </tr>
                </thead>
                <tbody>
                  {history.map((j) => (
                    <tr key={j.id} className="border-b border-border/60">
                      <td className="px-2 py-2 text-muted-foreground whitespace-nowrap">{new Date(j.created_at).toLocaleString('es-CO')}</td>
                      <td className="px-2 py-2 font-medium">{j.host}</td>
                      <td className="px-2 py-2">{j.kind === 'scan' ? 'Escaneo' : 'Aplicación'}</td>
                      <td className="px-2 py-2 hw-mono text-xs text-muted-foreground">{j.package || (j.kind === 'scan' ? (Array.isArray(j.packages) ? `${j.packages.length} updates` : '—') : '—')}</td>
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
