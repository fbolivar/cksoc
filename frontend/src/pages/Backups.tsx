/**
 * Respaldos de la base de datos (.pnnc). Solo admin.
 * Permite crear un respaldo manual, listar los existentes (manual/automatico),
 * verificar su integridad (sha256), descargarlos y eliminarlos.
 */
import { useEffect, useState } from 'react';
import { Database, Download, Trash2, ShieldCheck, Plus, Loader2, RefreshCw, HardDriveDownload, AlertTriangle, Clock, CloudOff, RotateCcw, Network } from 'lucide-react';
import { AxiosError } from 'axios';
import { backupsApi, type BackupItem, type RecoveryPosture, type NetCopyCfg } from '@/lib/backups';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

function fmtBytes(n: number): string {
  if (!n) return '—';
  const u = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${u[i]}`;
}

function fmtDate(iso: string): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleString('es-CO', { dateStyle: 'medium', timeStyle: 'short' });
}

export default function Backups() {
  const [items, setItems] = useState<BackupItem[]>([]);
  const [posture, setPosture] = useState<RecoveryPosture | null>(null);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState<Record<string, string>>({});
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);
  const [restoreTarget, setRestoreTarget] = useState<string | null>(null);
  const [restoreTyped, setRestoreTyped] = useState('');
  const [netCfg, setNetCfg] = useState<NetCopyCfg | null>(null);
  const [netPass, setNetPass] = useState('');
  const [netBusy, setNetBusy] = useState<'test' | 'save' | null>(null);
  const [netTest, setNetTest] = useState<{ ok: boolean; detail: string } | null>(null);

  const flash = (kind: 'ok' | 'err', text: string) => {
    setMsg({ kind, text });
    setTimeout(() => setMsg(null), 4500);
  };

  const emptyNet: NetCopyCfg = { enabled: false, path: '', user: '', domain: '', hasPassword: false, lastCopy: null };
  const netField = (k: 'path' | 'user' | 'domain', v: string) => setNetCfg((c) => ({ ...(c ?? emptyNet), [k]: v }));
  const netPayload = () => ({ enabled: netCfg?.enabled ?? false, path: netCfg?.path ?? '', user: netCfg?.user ?? '', domain: netCfg?.domain ?? '', password: netPass || undefined });
  const onNetTest = async () => {
    setNetBusy('test'); setNetTest(null);
    try { setNetTest(await backupsApi.netcopy.test(netPayload())); }
    catch (e) { setNetTest({ ok: false, detail: (e as { response?: { data?: { error?: string } } })?.response?.data?.error ?? 'Error de prueba' }); }
    finally { setNetBusy(null); }
  };
  const onNetSave = async () => {
    setNetBusy('save');
    try { const r = await backupsApi.netcopy.save(netPayload()); setNetCfg(r); setNetPass(''); setNetTest(null); flash('ok', 'Configuracion de copia en red guardada'); }
    catch (e) { flash('err', (e as { response?: { data?: { error?: string } } })?.response?.data?.error ?? 'No se pudo guardar'); }
    finally { setNetBusy(null); }
  };

  const load = async () => {
    setLoading(true);
    try {
      setItems(await backupsApi.list());
      backupsApi.posture().then(setPosture).catch(() => setPosture(null));
      backupsApi.netcopy.get().then(setNetCfg).catch(() => setNetCfg(null));
    } catch {
      flash('err', 'No se pudieron cargar los respaldos');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const onCreate = async () => {
    setCreating(true);
    try {
      const item = await backupsApi.create(note);
      setNote('');
      flash('ok', `Respaldo creado (${fmtBytes(item.fileBytes)})`);
      await load();
    } catch (err) {
      const ax = err as AxiosError<{ error?: string }>;
      flash('err', ax.response?.data?.error ?? 'No se pudo crear el respaldo');
    } finally {
      setCreating(false);
    }
  };

  const mark = (id: string, action: string) => setBusy((b) => ({ ...b, [id]: action }));
  const unmark = (id: string) => setBusy((b) => {
    const c = { ...b };
    delete c[id];
    return c;
  });

  const onVerify = async (id: string) => {
    mark(id, 'verify');
    try {
      const r = await backupsApi.verify(id);
      setItems((prev) => prev.map((it) => (it.id === id ? { ...it, integrity: r } : it)));
      flash(r === 'ok' ? 'ok' : 'err', r === 'ok' ? 'Integridad verificada (sha256 correcto)' : 'Respaldo corrupto');
    } catch {
      flash('err', 'No se pudo verificar');
    } finally {
      unmark(id);
    }
  };

  const onDownload = async (id: string) => {
    mark(id, 'download');
    try {
      await backupsApi.download(id);
    } catch {
      flash('err', 'No se pudo descargar');
    } finally {
      unmark(id);
    }
  };

  const onDelete = async (id: string) => {
    if (!confirm(`¿Eliminar el respaldo ${id}? Esta acción no se puede deshacer.`)) return;
    mark(id, 'delete');
    try {
      await backupsApi.remove(id);
      flash('ok', 'Respaldo eliminado');
      await load();
    } catch {
      flash('err', 'No se pudo eliminar');
    } finally {
      unmark(id);
    }
  };

  const doRestore = async () => {
    const id = restoreTarget;
    if (!id || restoreTyped.trim() !== id) return;
    setRestoreTarget(null);
    mark(id, 'restore');
    try {
      const r = await backupsApi.restore(id);
      flash('ok', `Restaurado desde ${id}. Respaldo de seguridad previo: ${r.safetyBackupId}`);
      await load();
    } catch (e) {
      flash('err', (e as { response?: { data?: { error?: string } } })?.response?.data?.error ?? 'No se pudo restaurar');
    } finally {
      unmark(id);
    }
  };

  const totalBytes = items.reduce((s, i) => s + i.fileBytes, 0);

  return (
    <div className="mx-auto max-w-5xl space-y-5">
      <div>
        <h1 className="hw-mono text-2xl font-bold tracking-tight">Respaldos</h1>
        <p className="text-sm text-muted-foreground">
          Copias de seguridad de la base de datos en formato <span className="font-mono text-brand">.bbg</span> · respaldo
          automático diario + creación manual
        </p>
      </div>

      {msg && (
        <div
          className={`rounded-md border px-3 py-2 text-sm ${
            msg.kind === 'ok'
              ? 'border-primary/40 bg-primary/10 text-foreground'
              : 'border-destructive/40 bg-destructive/10 text-destructive'
          }`}
        >
          {msg.text}
        </div>
      )}

      {/* Postura de recuperación: la verdad sobre qué tan protegido está el SOC */}
      {posture && (() => {
        const c = posture.estado === 'fail' ? '#ef4444' : posture.estado === 'warn' ? '#f59e0b' : '#22c55e';
        return (
          <div className="rounded-lg border p-4" style={{ borderColor: `${c}55`, background: `${c}0d` }}>
            <div className="mb-3 flex items-center gap-2">
              <ShieldCheck className="h-5 w-5" style={{ color: c }} />
              <p className="text-sm font-semibold">Postura de recuperación</p>
              <span className="ml-auto hw-mono text-[10px] uppercase tracking-widest" style={{ color: c }}>
                {posture.estado === 'ok' ? 'protegido' : posture.estado === 'warn' ? 'atención' : 'en riesgo'}
              </span>
            </div>
            <div className="grid gap-3 sm:grid-cols-4">
              <div><p className="flex items-center gap-1 text-[10px] uppercase text-muted-foreground"><Clock className="h-3 w-3" /> Último respaldo</p>
                <p className="text-sm font-semibold" style={{ color: posture.fresh ? '#22c55e' : '#f59e0b' }}>{posture.lastBackupAgeHours != null ? `hace ${Math.round(posture.lastBackupAgeHours)}h` : 'ninguno'}</p>
                <p className="text-[10px] text-muted-foreground/70">{posture.fresh ? 'fresco' : 'revisar el automático'}</p></div>
              <div><p className="text-[10px] uppercase text-muted-foreground">Respaldos</p>
                <p className="text-sm font-semibold">{posture.totalBackups} <span className="font-normal text-muted-foreground">/ {posture.retention} ret.</span></p>
                <p className="text-[10px] text-muted-foreground/70">{(posture.totalBytes / 1048576).toFixed(1)} MB</p></div>
              <div><p className="text-[10px] uppercase text-muted-foreground">Integridad</p>
                <p className="text-sm font-semibold">{posture.integrity.corrupto > 0 ? <span className="text-red-500">{posture.integrity.corrupto} corrupto</span> : posture.integrity.ok > 0 ? <span className="text-emerald-500">{posture.integrity.ok} verificado</span> : <span className="text-muted-foreground">sin verificar</span>}</p>
                <p className="text-[10px] text-muted-foreground/70">sha256</p></div>
              <div><p className="flex items-center gap-1 text-[10px] uppercase text-muted-foreground"><CloudOff className="h-3 w-3" /> Copia externa</p>
                <p className="text-sm font-semibold" style={{ color: posture.offsite ? '#22c55e' : '#f59e0b' }}>{posture.offsite ? 'sí' : 'no'}</p>
                <p className="text-[10px] text-muted-foreground/70 truncate" title={posture.location}>{posture.location}</p></div>
            </div>
            {posture.warnings.length > 0 && (
              <ul className="mt-3 space-y-1.5 border-t border-border/40 pt-3">
                {posture.warnings.map((w, i) => (
                  <li key={i} className="flex gap-2 text-[11px] leading-snug text-muted-foreground"><AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-500" /><span>{w}</span></li>
                ))}
              </ul>
            )}
            <p className="mt-2 text-[10px] text-muted-foreground/60"><b>Alcance:</b> {posture.scope}</p>
          </div>
        );
      })()}

      {/* Crear respaldo */}
      <div className="glass rounded-lg p-4">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
          <div className="flex-1">
            <label className="mb-1 block text-xs font-medium text-muted-foreground">Nota (opcional)</label>
            <Input
              placeholder="p. ej. antes de actualizar"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              maxLength={200}
            />
          </div>
          <Button onClick={onCreate} disabled={creating} size="lg">
            {creating ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
            {creating ? 'Creando…' : 'Crear respaldo'}
          </Button>
        </div>
      </div>

      {/* Copia en repositorio de red (misma red) */}
      <div className="glass space-y-3 rounded-lg p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-sm font-semibold"><Network className="h-4 w-4 text-brand" /> Copia en repositorio de red (misma red)</div>
          <label className="flex items-center gap-2 text-xs text-muted-foreground">
            <input type="checkbox" className="h-3.5 w-3.5 accent-brand" checked={netCfg?.enabled ?? false} onChange={(e) => setNetCfg((c) => ({ ...(c ?? emptyNet), enabled: e.target.checked }))} />
            Activar
          </label>
        </div>
        <p className="text-xs text-muted-foreground">Cada respaldo se copia tambien a una carpeta de red. Usa una ruta UNC <span className="font-mono text-foreground">\\servidor\recurso\carpeta</span> alcanzable desde el servidor del SOC, o una carpeta local montada. Las letras de unidad (Z:) no aplican aqui.</p>
        <div className="grid gap-2 sm:grid-cols-2">
          <input value={netCfg?.path ?? ''} onChange={(e) => netField('path', e.target.value)} placeholder="\\192.168.20.50\Respaldos\BBG" className="w-full rounded-md border border-border bg-secondary/40 px-3 py-2 font-mono text-xs outline-none focus:border-primary sm:col-span-2" />
          <input value={netCfg?.user ?? ''} onChange={(e) => netField('user', e.target.value)} placeholder="Usuario (si el recurso lo pide)" className="w-full rounded-md border border-border bg-secondary/40 px-3 py-2 text-sm outline-none focus:border-primary" />
          <input value={netCfg?.domain ?? ''} onChange={(e) => netField('domain', e.target.value)} placeholder="Dominio (opcional)" className="w-full rounded-md border border-border bg-secondary/40 px-3 py-2 text-sm outline-none focus:border-primary" />
          <input type="password" value={netPass} onChange={(e) => setNetPass(e.target.value)} placeholder={netCfg?.hasPassword ? 'Contrasena guardada (vacio = conservar)' : 'Contrasena (si aplica)'} className="w-full rounded-md border border-border bg-secondary/40 px-3 py-2 text-sm outline-none focus:border-primary sm:col-span-2" />
        </div>
        {netTest && (<div className={`rounded-md px-3 py-2 text-xs ${netTest.ok ? 'bg-emerald-500/10 text-emerald-600' : 'bg-amber-500/10 text-amber-700'}`}>{netTest.ok ? 'Correcto: ' : 'Error: '}{netTest.detail}</div>)}
        {netCfg?.lastCopy && (<p className="text-[10px] text-muted-foreground/80">Ultima copia: {new Date(netCfg.lastCopy.at).toLocaleString()} ({netCfg.lastCopy.ok ? 'OK' : 'fallo'}) {netCfg.lastCopy.detail}</p>)}
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => void onNetTest()} disabled={netBusy !== null || !(netCfg?.path)}>{netBusy === 'test' ? <Loader2 className="h-4 w-4 animate-spin" /> : null} Probar conexion</Button>
          <Button size="sm" onClick={() => void onNetSave()} disabled={netBusy !== null}>{netBusy === 'save' ? <Loader2 className="h-4 w-4 animate-spin" /> : null} Guardar</Button>
        </div>
      </div>

      {/* Lista */}
      <div className="glass rounded-lg">
        <div className="flex items-center justify-between border-b border-border/60 px-4 py-3">
          <div className="flex items-center gap-2 text-sm font-medium">
            <Database className="h-4 w-4 text-brand" />
            {items.length} respaldo{items.length === 1 ? '' : 's'} · {fmtBytes(totalBytes)}
          </div>
          <button onClick={() => void load()} className="text-muted-foreground hover:text-foreground" title="Refrescar">
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>

        {loading ? (
          <div className="p-8 text-center text-sm text-muted-foreground">Cargando…</div>
        ) : items.length === 0 ? (
          <div className="flex flex-col items-center gap-2 p-10 text-center text-muted-foreground">
            <HardDriveDownload className="h-8 w-8 opacity-50" />
            <p className="text-sm">Aún no hay respaldos. Crea el primero arriba.</p>
          </div>
        ) : (
          <div className="divide-y divide-border/50">
            {items.map((b) => (
              <div key={b.id} className="flex flex-wrap items-center gap-3 px-4 py-3">
                <div className="min-w-0 flex-1">
                  <p className="truncate font-mono text-sm">{b.id}</p>
                  <p className="text-xs text-muted-foreground">
                    {fmtDate(b.createdAt)} · {fmtBytes(b.fileBytes)}
                    {b.note ? ` · ${b.note}` : ''}
                  </p>
                </div>
                <span
                  className={`rounded px-2 py-0.5 text-[11px] font-medium ${
                    b.origin === 'automatico' ? 'bg-secondary text-muted-foreground' : 'bg-brand/15 text-brand'
                  }`}
                >
                  {b.origin === 'automatico' ? 'Automático' : 'Manual'}
                </span>
                {b.integrity === 'ok' && (
                  <span className="flex items-center gap-1 text-[11px] text-primary">
                    <ShieldCheck className="h-3 w-3" /> íntegro
                  </span>
                )}
                {b.integrity === 'corrupto' && (
                  <span className="text-[11px] text-destructive">corrupto</span>
                )}
                <div className="flex items-center gap-1">
                  <Button variant="ghost" size="sm" onClick={() => void onVerify(b.id)} disabled={!!busy[b.id]} title="Verificar integridad">
                    {busy[b.id] === 'verify' ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
                  </Button>
                  <Button variant="ghost" size="sm" onClick={() => void onDownload(b.id)} disabled={!!busy[b.id]} title="Descargar .bbg">
                    {busy[b.id] === 'download' ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => { setRestoreTarget(b.id); setRestoreTyped(''); }}
                    disabled={!!busy[b.id]}
                    title="Restaurar esta copia (reemplaza la BD actual)"
                    className="text-amber-600 hover:text-amber-700"
                  >
                    {busy[b.id] === 'restore' ? <Loader2 className="h-4 w-4 animate-spin" /> : <RotateCcw className="h-4 w-4" />}
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => void onDelete(b.id)}
                    disabled={!!busy[b.id] || items.length <= 1}
                    title={items.length <= 1 ? 'No se puede borrar el ultimo respaldo disponible' : 'Eliminar'}
                    className="text-destructive/80 hover:text-destructive"
                  >
                    {busy[b.id] === 'delete' ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <p className="text-center text-[11px] text-muted-foreground/70">
        El formato .bbg es un contenedor propio: volcado SQL comprimido con metadatos y verificación de integridad
        (SHA-256). El respaldo automático corre a diario y conserva los últimos configurados.
      </p>
      {restoreTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={() => setRestoreTarget(null)}>
          <div className="w-full max-w-lg rounded-lg border border-border bg-background p-5 shadow-xl" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center gap-2 text-amber-600"><AlertTriangle className="h-5 w-5" /><h3 className="text-lg font-semibold">Restaurar base de datos</h3></div>
            <p className="mt-3 text-sm text-muted-foreground">Vas a <b className="text-foreground">reemplazar toda la base de datos actual</b> con el respaldo <span className="font-mono text-foreground">{restoreTarget}</span>. Antes se crea un respaldo de seguridad del estado actual y la operación es atómica (si algo falla, no cambia nada). La app puede quedar unos segundos no disponible.</p>
            <p className="mt-3 text-sm">Para confirmar, escribe el nombre exacto del respaldo:</p>
            <input value={restoreTyped} onChange={(e) => setRestoreTyped(e.target.value)} placeholder={restoreTarget ?? ''} autoFocus className="mt-1 w-full rounded-md border border-border bg-secondary/40 px-3 py-2 font-mono text-sm outline-none focus:border-primary" />
            <div className="mt-4 flex justify-end gap-2">
              <Button variant="ghost" size="sm" onClick={() => setRestoreTarget(null)}>Cancelar</Button>
              <Button size="sm" disabled={restoreTyped.trim() !== restoreTarget} onClick={() => void doRestore()} className="bg-amber-600 text-white hover:bg-amber-700">Restaurar ahora</Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
