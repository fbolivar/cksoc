/**
 * On-call / Turnos de guardia. Muestra quién está de guardia ahora, el calendario
 * de turnos próximos, y (admin) permite crear/borrar turnos y probar el
 * escalamiento por correo al analista de guardia.
 */
import { useEffect, useState } from 'react';
import { AxiosError } from 'axios';
import { CalendarClock, RefreshCw, Loader2, Plus, Trash2, Send, ShieldCheck } from 'lucide-react';
import { oncallApi, type Shift, type EscalationResult } from '@/lib/oncall';
import { usersApi, type User } from '@/lib/users';
import { useAuth } from '@/lib/auth';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

function fmt(iso: string): string {
  return new Date(iso).toLocaleString('es-CO', { weekday: 'short', day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' });
}
// Valor para <input datetime-local> a partir de ahora + horas.
function localInput(d: Date): string {
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}

export default function OnCall() {
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';
  const [current, setCurrent] = useState<Shift | null>(null);
  const [shifts, setShifts] = useState<Shift[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [testMsg, setTestMsg] = useState<string | null>(null);

  // form
  const [userId, setUserId] = useState('');
  const [startsAt, setStartsAt] = useState(localInput(new Date()));
  const [endsAt, setEndsAt] = useState(localInput(new Date(Date.now() + 8 * 3600e3)));
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);

  async function load() {
    setLoading(true); setError(null);
    try {
      const [cur, list] = await Promise.all([oncallApi.current(), oncallApi.list()]);
      setCurrent(cur); setShifts(list);
    } catch (e) { setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudieron cargar los turnos'); }
    finally { setLoading(false); }
  }
  useEffect(() => {
    load();
    if (isAdmin) usersApi.list().then((u) => setUsers(u.filter((x) => x.isActive))).catch(() => undefined);
  }, [isAdmin]);

  async function create() {
    if (!userId) { setError('Elige un analista'); return; }
    setBusy(true); setError(null);
    try {
      await oncallApi.create({ userId, startsAt: new Date(startsAt).toISOString(), endsAt: new Date(endsAt).toISOString(), note: note.trim() || undefined });
      setNote('');
      await load();
    } catch (e) { setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo crear el turno'); }
    finally { setBusy(false); }
  }
  async function remove(id: string) {
    if (!confirm('¿Borrar este turno?')) return;
    await oncallApi.remove(id).catch(() => undefined);
    await load();
  }
  async function test() {
    setTestMsg('Enviando…');
    try {
      const r: EscalationResult = await oncallApi.test();
      setTestMsg(r.delivered ? `✓ Enviado a ${r.to.join(', ')} (${r.reason})` : `✗ No enviado: ${r.reason}`);
    } catch { setTestMsg('✗ Error al enviar la prueba'); }
  }

  return (
    <div className="mx-auto max-w-4xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 hw-mono text-2xl font-bold tracking-tight"><CalendarClock className="h-6 w-6 text-neon" /> On-call · Turnos</h1>
          <p className="text-sm text-muted-foreground">Analista de guardia y escalamiento de incidentes por Telegram y correo</p>
        </div>
        <Button variant="outline" size="sm" onClick={load} disabled={loading}><RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} /> Actualizar</Button>
      </div>

      {error && <Card><CardContent className="p-4 text-sm text-amber-700">{error}</CardContent></Card>}

      {/* De guardia ahora */}
      <Card className={current ? 'border-primary/40' : ''}>
        <CardContent className="flex flex-wrap items-center gap-3 p-4">
          <ShieldCheck className={`h-8 w-8 ${current ? 'text-primary' : 'text-muted-foreground/40'}`} />
          <div className="min-w-0 flex-1">
            <p className="text-xs uppercase tracking-wide text-muted-foreground">De guardia ahora</p>
            {current ? (
              <>
                <p className="text-lg font-semibold">{current.userName}</p>
                <p className="text-xs text-muted-foreground">{current.userEmail} · hasta {fmt(current.endsAt)}{current.note ? ` · ${current.note}` : ''}</p>
              </>
            ) : (
              <>
                <p className="text-sm font-medium text-amber-600">Sin guardia asignada</p>
                <p className="text-xs text-muted-foreground">El escalamiento de incidentes críticos va a los <b>administradores</b>, por <b>Telegram</b> (grupo del equipo) y correo si está configurado. Define turnos abajo para dirigirlo a un analista responsable por franja.</p>
              </>
            )}
          </div>
          {isAdmin && (
            <Button variant="outline" size="sm" onClick={test}><Send className="h-4 w-4" /> Probar escalamiento</Button>
          )}
        </CardContent>
      </Card>
      {testMsg && <p className="text-center text-xs text-muted-foreground">{testMsg}</p>}

      {/* Nuevo turno (admin) */}
      {isAdmin && (
        <Card>
          <CardContent className="space-y-3 p-4">
            <p className="text-sm font-semibold">Nuevo turno</p>
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-1"><label className="text-xs text-muted-foreground">Analista</label>
                <select value={userId} onChange={(e) => setUserId(e.target.value)} className="h-9 w-full rounded-md border border-input bg-background/60 px-2 text-sm">
                  <option value="">— elige —</option>
                  {users.map((u) => <option key={u.id} value={u.id}>{u.fullName} ({u.role})</option>)}
                </select>
              </div>
              <div className="space-y-1"><label className="text-xs text-muted-foreground">Nota (opcional)</label>
                <Input value={note} onChange={(e) => setNote(e.target.value)} placeholder="p. ej. guardia nocturna" /></div>
              <div className="space-y-1"><label className="text-xs text-muted-foreground">Inicio</label>
                <Input type="datetime-local" value={startsAt} onChange={(e) => setStartsAt(e.target.value)} /></div>
              <div className="space-y-1"><label className="text-xs text-muted-foreground">Fin</label>
                <Input type="datetime-local" value={endsAt} onChange={(e) => setEndsAt(e.target.value)} /></div>
            </div>
            <div className="flex justify-end">
              <Button onClick={create} disabled={busy}>{busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />} Crear turno</Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Calendario de turnos */}
      <Card>
        <CardContent className="p-0">
          <div className="border-b border-border/60 px-4 py-2.5 text-sm font-semibold">Turnos (últimos 7 días → próximos 30)</div>
          {loading && shifts.length === 0 ? (
            <p className="flex items-center gap-2 p-4 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Cargando…</p>
          ) : shifts.length === 0 ? (
            <p className="py-8 text-center text-sm text-muted-foreground">Sin turnos. {isAdmin ? 'Crea uno arriba.' : ''}</p>
          ) : (
            <div className="divide-y divide-border/30">
              {shifts.map((s) => {
                const now = Date.now();
                const active = new Date(s.startsAt).getTime() <= now && new Date(s.endsAt).getTime() > now;
                return (
                  <div key={s.id} className="flex flex-wrap items-center justify-between gap-2 px-4 py-2.5">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{s.userName}</span>
                        {active && <span className="rounded bg-primary/15 px-1.5 py-0.5 text-[10px] font-semibold text-primary">EN GUARDIA</span>}
                      </div>
                      <p className="text-xs text-muted-foreground">{fmt(s.startsAt)} → {fmt(s.endsAt)}{s.note ? ` · ${s.note}` : ''}</p>
                    </div>
                    {isAdmin && <Button size="sm" variant="ghost" onClick={() => remove(s.id)}><Trash2 className="h-4 w-4 text-destructive" /></Button>}
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
