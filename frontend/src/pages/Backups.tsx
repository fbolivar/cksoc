/**
 * Respaldos de la base de datos (.pnnc). Solo admin.
 * Permite crear un respaldo manual, listar los existentes (manual/automatico),
 * verificar su integridad (sha256), descargarlos y eliminarlos.
 */
import { useEffect, useState } from 'react';
import { Database, Download, Trash2, ShieldCheck, Plus, Loader2, RefreshCw, HardDriveDownload, AlertTriangle, Clock, CloudOff } from 'lucide-react';
import { AxiosError } from 'axios';
import { backupsApi, type BackupItem, type RecoveryPosture } from '@/lib/backups';
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

  const flash = (kind: 'ok' | 'err', text: string) => {
    setMsg({ kind, text });
    setTimeout(() => setMsg(null), 4500);
  };

  const load = async () => {
    setLoading(true);
    try {
      setItems(await backupsApi.list());
      backupsApi.posture().then(setPosture).catch(() => setPosture(null));
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

  const totalBytes = items.reduce((s, i) => s + i.fileBytes, 0);

  return (
    <div className="mx-auto max-w-5xl space-y-5">
      <div>
        <h1 className="hw-mono text-2xl font-bold tracking-tight">Respaldos</h1>
        <p className="text-sm text-muted-foreground">
          Copias de seguridad de la base de datos en formato <span className="font-mono text-brand">.pnnc</span> · respaldo
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
                  <Button variant="ghost" size="sm" onClick={() => void onDownload(b.id)} disabled={!!busy[b.id]} title="Descargar .pnnc">
                    {busy[b.id] === 'download' ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => void onDelete(b.id)}
                    disabled={!!busy[b.id]}
                    title="Eliminar"
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
        El formato .pnnc es un contenedor propio: volcado SQL comprimido con metadatos y verificación de integridad
        (SHA-256). El respaldo automático corre a diario y conserva los últimos configurados.
      </p>
    </div>
  );
}
