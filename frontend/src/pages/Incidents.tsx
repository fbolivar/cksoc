/**
 * Gestion de Incidentes/Casos: lista con filtros, creacion, y detalle con
 * timeline (comentarios + eventos del sistema), cambio de estado y asignacion.
 */
import { useEffect, useState } from 'react';
import { AxiosError } from 'axios';
import { Briefcase, RefreshCw, Loader2, Plus, ArrowLeft, X, Send, User, Clock } from 'lucide-react';
import { incidentsApi, SEV, ST, type IncidentListItem, type IncidentDetail, type Severity, type Status } from '@/lib/incidents';
import { useAuth } from '@/lib/auth';
import { downloadCsv, fileStamp, type CsvCol } from '@/lib/csv';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { ExportButton } from '@/components/shared/ExportButton';

const STATUSES: Status[] = ['abierto', 'en_curso', 'resuelto', 'cerrado'];
const SEVS: Severity[] = ['critica', 'alta', 'media', 'baja'];

const INCIDENT_COLS: CsvCol<IncidentListItem>[] = [
  { label: 'Título', get: (i) => i.title },
  { label: 'Severidad', get: (i) => SEV[i.severity].label },
  { label: 'Estado', get: (i) => ST[i.status].label },
  { label: 'Asignado a', get: (i) => i.assigneeName ?? '' },
  { label: 'Creado por', get: (i) => i.creatorName ?? '' },
  { label: 'Notas', get: (i) => i.notes },
  { label: 'Creado', get: (i) => i.createdAt },
  { label: 'Actualizado', get: (i) => i.updatedAt },
];

function Chip({ color, label }: { color: string; label: string }) {
  return <span className="inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-semibold" style={{ background: `${color}22`, color }}>{label}</span>;
}

export default function Incidents() {
  const { user } = useAuth();
  const canManage = user?.role === 'admin' || user?.role === 'analista';
  const [list, setList] = useState<IncidentListItem[] | null>(null);
  const [statusF, setStatusF] = useState('');
  const [sel, setSel] = useState<string | null>(null);
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [users, setUsers] = useState<{ id: string; name: string; role: string }[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState('');

  async function loadList() {
    setLoading(true); setError(null);
    try { setList(await incidentsApi.list(statusF ? { status: statusF } : {})); }
    catch (e) { setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo cargar incidentes'); }
    finally { setLoading(false); }
  }
  useEffect(() => { loadList(); /* eslint-disable-next-line */ }, [statusF]);
  useEffect(() => { if (canManage) incidentsApi.users().then(setUsers).catch(() => undefined); }, [canManage]);
  useEffect(() => {
    if (!sel) { setDetail(null); return; }
    incidentsApi.get(sel).then(setDetail).catch(() => setDetail(null));
  }, [sel]);

  async function patch(p: { status?: Status; severity?: Severity; assigneeId?: string | null }) {
    if (!sel) return;
    setBusy(true);
    try { setDetail(await incidentsApi.update(sel, p)); await loadList(); }
    finally { setBusy(false); }
  }
  async function sendNote() {
    if (!sel || !note.trim()) return;
    setBusy(true);
    try { setDetail(await incidentsApi.addNote(sel, note.trim())); setNote(''); }
    finally { setBusy(false); }
  }

  return (
    <div className="mx-auto max-w-6xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
            <Briefcase className="h-6 w-6 text-neon" /> Incidentes
          </h1>
          <p className="text-sm text-muted-foreground">Gestión y seguimiento de casos del SOC</p>
        </div>
        <div className="flex items-center gap-2">
          {sel ? (
            <Button variant="outline" size="sm" onClick={() => setSel(null)}><ArrowLeft className="h-4 w-4" /> Volver</Button>
          ) : (
            <>
              {canManage && <Button size="sm" onClick={() => setShowCreate(true)}><Plus className="h-4 w-4" /> Nuevo</Button>}
              <ExportButton onExport={() => downloadCsv(`incidentes-${fileStamp()}.csv`, list ?? [], INCIDENT_COLS)} disabled={!list || list.length === 0} />
              <Button variant="outline" size="sm" onClick={loadList} disabled={loading}><RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} /></Button>
            </>
          )}
        </div>
      </div>

      {error && <Card><CardContent className="p-4 text-sm text-amber-200">{error}</CardContent></Card>}

      {/* Lista */}
      {!sel && (
        <>
          <div className="flex flex-wrap gap-1 border-b border-border/60">
            {[['', 'Todos'], ...STATUSES.map((s) => [s, ST[s].label] as [string, string])].map(([v, label]) => (
              <button key={v} onClick={() => setStatusF(v)}
                className={`px-3 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${statusF === v ? 'border-primary text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground'}`}>
                {label}
              </button>
            ))}
          </div>
          {loading && !list ? (
            <p className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Cargando…</p>
          ) : (list ?? []).length === 0 ? (
            <Card><CardContent className="py-12 text-center text-sm text-muted-foreground">No hay incidentes{statusF ? ` en estado "${ST[statusF as Status]?.label}"` : ''}.</CardContent></Card>
          ) : (
            <div className="space-y-2">
              {(list ?? []).map((i) => (
                <button key={i.id} onClick={() => setSel(i.id)} className="block w-full text-left">
                  <Card className="transition-colors hover:border-primary/40">
                    <CardContent className="flex flex-wrap items-center gap-3 p-3">
                      <Chip color={SEV[i.severity].color} label={SEV[i.severity].label} />
                      <Chip color={ST[i.status].color} label={ST[i.status].label} />
                      <span className="flex-1 truncate text-sm font-medium">{i.title}</span>
                      <span className="flex items-center gap-1 text-xs text-muted-foreground">
                        {i.assigneeName ? <><User className="h-3 w-3" />{i.assigneeName}</> : 'sin asignar'}
                      </span>
                      <span className="text-[11px] text-muted-foreground/60">{i.notes} nota(s) · {new Date(i.createdAt).toLocaleDateString('es-CO')}</span>
                    </CardContent>
                  </Card>
                </button>
              ))}
            </div>
          )}
        </>
      )}

      {/* Detalle */}
      {sel && (!detail ? (
        <p className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Cargando…</p>
      ) : (
        <div className="grid gap-4 lg:grid-cols-3">
          <div className="space-y-4 lg:col-span-2">
            <Card>
              <CardContent className="p-4">
                <div className="mb-2 flex flex-wrap items-center gap-2">
                  <Chip color={SEV[detail.severity].color} label={SEV[detail.severity].label} />
                  <Chip color={ST[detail.status].color} label={ST[detail.status].label} />
                </div>
                <h2 className="text-lg font-semibold">{detail.title}</h2>
                {detail.description && <p className="mt-1 text-sm text-muted-foreground">{detail.description}</p>}
                <p className="mt-2 text-xs text-muted-foreground/70">
                  Creado por {detail.creatorName ?? '—'} · {new Date(detail.createdAt).toLocaleString('es-CO')}
                  {detail.closedAt ? ` · cerrado ${new Date(detail.closedAt).toLocaleString('es-CO')}` : ''}
                </p>
                {(detail.source?.ip || detail.source?.ruleId || detail.source?.agent) && (
                  <p className="mt-2 rounded-md border border-border/50 bg-secondary/30 p-2 text-[11px] text-muted-foreground">
                    Origen: {detail.source.ip ? `IP ${detail.source.ip} · ` : ''}{detail.source.agent ? `${detail.source.agent} · ` : ''}{detail.source.ruleId ? `regla ${detail.source.ruleId}` : ''}
                  </p>
                )}
              </CardContent>
            </Card>

            {/* Timeline */}
            <Card>
              <CardHeader><CardTitle className="flex items-center gap-2 text-muted-foreground"><Clock className="h-4 w-4" /> Bitácora</CardTitle></CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {detail.timeline.map((t) => (
                    <div key={t.id} className="flex gap-3">
                      <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${t.kind === 'system' ? 'bg-muted-foreground/40' : 'bg-neon'}`} />
                      <div className="flex-1">
                        <p className={`text-sm ${t.kind === 'system' ? 'italic text-muted-foreground' : ''}`}>{t.note}</p>
                        <p className="text-[10px] text-muted-foreground/60">{t.authorName ?? '—'} · {new Date(t.createdAt).toLocaleString('es-CO')}</p>
                      </div>
                    </div>
                  ))}
                </div>
                {canManage && (
                  <div className="mt-4 flex gap-2 border-t border-border/40 pt-3">
                    <Textarea value={note} onChange={(e) => setNote(e.target.value)} placeholder="Agregar comentario…" className="min-h-[40px] flex-1" />
                    <Button size="sm" onClick={sendNote} disabled={busy || !note.trim()}><Send className="h-4 w-4" /></Button>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Acciones */}
          <Card className="h-fit">
            <CardHeader><CardTitle className="text-muted-foreground">Gestión</CardTitle></CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-1.5">
                <label className="text-xs text-muted-foreground">Estado</label>
                <select value={detail.status} disabled={!canManage || busy} onChange={(e) => patch({ status: e.target.value as Status })}
                  className="h-9 w-full rounded-md border border-input bg-background/60 px-2 text-sm disabled:opacity-60">
                  {STATUSES.map((s) => <option key={s} value={s}>{ST[s].label}</option>)}
                </select>
              </div>
              <div className="space-y-1.5">
                <label className="text-xs text-muted-foreground">Severidad</label>
                <select value={detail.severity} disabled={!canManage || busy} onChange={(e) => patch({ severity: e.target.value as Severity })}
                  className="h-9 w-full rounded-md border border-input bg-background/60 px-2 text-sm disabled:opacity-60">
                  {SEVS.map((s) => <option key={s} value={s}>{SEV[s].label}</option>)}
                </select>
              </div>
              <div className="space-y-1.5">
                <label className="text-xs text-muted-foreground">Asignado a</label>
                <select value={detail.assigneeId ?? ''} disabled={!canManage || busy} onChange={(e) => patch({ assigneeId: e.target.value || null })}
                  className="h-9 w-full rounded-md border border-input bg-background/60 px-2 text-sm disabled:opacity-60">
                  <option value="">Sin asignar</option>
                  {users.map((u) => <option key={u.id} value={u.id}>{u.name}</option>)}
                </select>
              </div>
            </CardContent>
          </Card>
        </div>
      ))}

      {/* Modal crear */}
      {showCreate && <CreateModal users={users} onClose={() => setShowCreate(false)} onCreated={(id) => { setShowCreate(false); loadList(); setSel(id); }} />}
    </div>
  );
}

function CreateModal({ onClose, onCreated }: { users: { id: string; name: string; role: string }[]; onClose: () => void; onCreated: (id: string) => void }) {
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState<Severity>('media');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function create() {
    if (title.trim().length < 3) { setErr('El título debe tener al menos 3 caracteres'); return; }
    setBusy(true); setErr(null);
    try {
      const inc = await incidentsApi.create({ title: title.trim(), description: description.trim() || undefined, severity });
      onCreated(inc.id);
    } catch (e) {
      setErr((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo crear');
    } finally { setBusy(false); }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div className="w-full max-w-lg rounded-lg border border-border/70 bg-card shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between border-b border-border/60 px-5 py-3">
          <h3 className="font-semibold">Nuevo incidente</h3>
          <Button variant="ghost" size="icon" onClick={onClose}><X className="h-4 w-4" /></Button>
        </div>
        <div className="space-y-3 p-5">
          {err && <p className="text-sm text-red-400">{err}</p>}
          <div className="space-y-1.5">
            <label className="text-xs text-muted-foreground">Título</label>
            <Input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="p. ej. Fuerza bruta VPN desde IP externa" />
          </div>
          <div className="space-y-1.5">
            <label className="text-xs text-muted-foreground">Descripción</label>
            <Textarea value={description} onChange={(e) => setDescription(e.target.value)} className="min-h-[90px]" />
          </div>
          <div className="space-y-1.5">
            <label className="text-xs text-muted-foreground">Severidad</label>
            <select value={severity} onChange={(e) => setSeverity(e.target.value as Severity)} className="h-9 w-full rounded-md border border-input bg-background/60 px-2 text-sm">
              {SEVS.map((s) => <option key={s} value={s}>{SEV[s].label}</option>)}
            </select>
          </div>
          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={onClose} disabled={busy}>Cancelar</Button>
            <Button onClick={create} disabled={busy}>{busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />} Crear</Button>
          </div>
        </div>
      </div>
    </div>
  );
}
