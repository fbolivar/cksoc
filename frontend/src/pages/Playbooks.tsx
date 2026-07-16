/**
 * SOAR / Playbooks: respuesta automatizada ante patrones de alerta.
 * Seguridad visible: modo Simulación por defecto; para ejecutar de verdad hay
 * que ponerlo en Activo Y habilitarlo. La acción "Probar" muestra qué haría.
 */
import { useEffect, useState } from 'react';
import { Zap, Plus, Play, Trash2, Power, FlaskConical, ShieldAlert, Loader2, History, X } from 'lucide-react';
import { AxiosError } from 'axios';
import {
  playbooksApi, ACTION_LABELS, type Playbook, type PlaybookInput, type ActionType, type PlaybookRun,
} from '@/lib/playbooks';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

const ACTIONS: ActionType[] = ['block_ip', 'create_incident', 'notify'];

const empty: PlaybookInput = {
  name: '', description: '', mode: 'simulacion', enabled: false,
  conditions: { minLevel: 12 }, actions: [{ type: 'notify' }], cooldownMin: 30,
};

function csv(arr?: string[]): string { return (arr ?? []).join(', '); }
function toArr(s: string): string[] | undefined {
  const a = s.split(',').map((x) => x.trim()).filter(Boolean);
  return a.length ? a : undefined;
}

export default function Playbooks() {
  const [items, setItems] = useState<Playbook[]>([]);
  const [runs, setRuns] = useState<PlaybookRun[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState<PlaybookInput & { minLevel?: string; ruleIds?: string; mitre?: string; agents?: string }>({ ...empty });
  const [msg, setMsg] = useState<{ k: 'ok' | 'err'; t: string } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const flash = (k: 'ok' | 'err', t: string) => { setMsg({ k, t }); setTimeout(() => setMsg(null), 5000); };

  const load = async () => {
    setLoading(true);
    try {
      const [pb, r] = await Promise.all([playbooksApi.list(), playbooksApi.runs()]);
      setItems(pb); setRuns(r);
    } finally { setLoading(false); }
  };
  useEffect(() => { void load(); }, []);

  const submit = async () => {
    const payload: PlaybookInput = {
      name: form.name.trim(),
      description: form.description,
      mode: form.mode,
      enabled: form.enabled,
      cooldownMin: form.cooldownMin,
      conditions: {
        minLevel: form.minLevel ? Number(form.minLevel) : undefined,
        ruleIds: toArr(form.ruleIds ?? ''),
        mitre: toArr(form.mitre ?? ''),
        agents: toArr(form.agents ?? ''),
      },
      actions: form.actions,
    };
    if (!payload.name || payload.actions.length === 0) { flash('err', 'Nombre y al menos una acción son obligatorios'); return; }
    try {
      await playbooksApi.create(payload);
      setShowForm(false); setForm({ ...empty });
      flash('ok', 'Playbook creado (en simulación hasta que lo actives)');
      await load();
    } catch (e) {
      flash('err', (e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo crear');
    }
  };

  const toggleEnabled = async (p: Playbook) => {
    setBusy(p.id);
    try { await playbooksApi.update(p.id, { enabled: !p.enabled }); await load(); }
    finally { setBusy(null); }
  };
  const toggleMode = async (p: Playbook) => {
    const next = p.mode === 'activo' ? 'simulacion' : 'activo';
    if (next === 'activo' && !confirm(`¿Poner "${p.name}" en modo ACTIVO? Ejecutará acciones reales (incluido bloquear IPs en el FortiGate).`)) return;
    setBusy(p.id);
    try { await playbooksApi.update(p.id, { mode: next }); await load(); }
    finally { setBusy(null); }
  };
  const test = async (p: Playbook) => {
    setBusy(p.id);
    try {
      const r = await playbooksApi.test(p.id);
      flash('ok', r.matched ? `Prueba: ${r.results.map((x) => `${x.type}=${x.status}`).join(', ')}` : 'La alerta de ejemplo no cumple las condiciones');
      await load();
    } finally { setBusy(null); }
  };
  const remove = async (p: Playbook) => {
    if (!confirm(`¿Eliminar el playbook "${p.name}"?`)) return;
    setBusy(p.id);
    try { await playbooksApi.remove(p.id); await load(); } finally { setBusy(null); }
  };

  return (
    <div className="mx-auto max-w-5xl space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight"><Zap className="h-6 w-6 text-brand" /> Playbooks (SOAR)</h1>
          <p className="text-sm text-muted-foreground">Respuesta automatizada — el SOC actúa solo ante ciertos patrones</p>
        </div>
        <Button onClick={() => setShowForm((s) => !s)}><Plus className="h-4 w-4" /> Nuevo playbook</Button>
      </div>

      {msg && (
        <div className={`rounded-md border px-3 py-2 text-sm ${msg.k === 'ok' ? 'border-primary/40 bg-primary/10 text-foreground' : 'border-destructive/40 bg-destructive/10 text-destructive-foreground'}`}>{msg.t}</div>
      )}

      {/* Aviso de seguridad */}
      <div className="flex items-start gap-2 rounded-md border border-warn/30 bg-warn/10 px-3 py-2 text-xs text-foreground">
        <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-warn" />
        <span>Un playbook solo ejecuta acciones reales si está en modo <b>Activo</b> <b>y</b> habilitado. En <b>Simulación</b> registra lo que haría sin tocar nada. El bloqueo de IP respeta la lista blanca.</span>
      </div>

      {/* Formulario */}
      {showForm && (
        <div className="glass space-y-3 rounded-lg p-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold">Nuevo playbook</h3>
            <button onClick={() => setShowForm(false)}><X className="h-4 w-4 text-muted-foreground" /></button>
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div><label className="mb-1 block text-xs text-muted-foreground">Nombre</label><Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></div>
            <div><label className="mb-1 block text-xs text-muted-foreground">Descripción</label><Input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></div>
          </div>
          <p className="text-xs font-medium text-muted-foreground">Condiciones (todas deben cumplirse; vacío = ignorar)</p>
          <div className="grid gap-3 sm:grid-cols-4">
            <div><label className="mb-1 block text-xs text-muted-foreground">Nivel mínimo</label><Input type="number" value={form.minLevel ?? '12'} onChange={(e) => setForm({ ...form, minLevel: e.target.value })} /></div>
            <div><label className="mb-1 block text-xs text-muted-foreground">Reglas (id, coma)</label><Input value={form.ruleIds ?? ''} onChange={(e) => setForm({ ...form, ruleIds: e.target.value })} /></div>
            <div><label className="mb-1 block text-xs text-muted-foreground">MITRE (coma)</label><Input value={form.mitre ?? ''} onChange={(e) => setForm({ ...form, mitre: e.target.value })} /></div>
            <div><label className="mb-1 block text-xs text-muted-foreground">Agentes (coma)</label><Input value={form.agents ?? ''} onChange={(e) => setForm({ ...form, agents: e.target.value })} /></div>
          </div>
          <p className="text-xs font-medium text-muted-foreground">Acciones</p>
          <div className="flex flex-wrap gap-3">
            {ACTIONS.map((a) => {
              const on = form.actions.some((x) => x.type === a);
              return (
                <label key={a} className="flex items-center gap-1.5 text-sm">
                  <input type="checkbox" checked={on} onChange={(e) => setForm({ ...form, actions: e.target.checked ? [...form.actions, { type: a }] : form.actions.filter((x) => x.type !== a) })} />
                  {ACTION_LABELS[a]}
                </label>
              );
            })}
          </div>
          <div className="flex flex-wrap items-center gap-4">
            <div><label className="mb-1 block text-xs text-muted-foreground">Cooldown (min)</label><Input type="number" className="w-24" value={form.cooldownMin} onChange={(e) => setForm({ ...form, cooldownMin: Number(e.target.value) })} /></div>
            <label className="mt-4 flex items-center gap-1.5 text-sm">
              <input type="checkbox" checked={form.mode === 'activo'} onChange={(e) => setForm({ ...form, mode: e.target.checked ? 'activo' : 'simulacion' })} /> Modo activo (ejecuta de verdad)
            </label>
          </div>
          <Button onClick={submit} size="lg" className="w-full sm:w-auto">Crear playbook</Button>
        </div>
      )}

      {/* Lista */}
      {loading ? (
        <div className="glass rounded-lg p-8 text-center text-sm text-muted-foreground">Cargando…</div>
      ) : items.length === 0 ? (
        <div className="glass rounded-lg p-10 text-center text-sm text-muted-foreground">Aún no hay playbooks. Crea el primero.</div>
      ) : (
        <div className="space-y-2">
          {items.map((p) => (
            <div key={p.id} className="glass rounded-lg p-4">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-medium">{p.name}</span>
                    <span className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${p.mode === 'activo' ? 'bg-destructive/20 text-destructive-foreground' : 'bg-secondary text-muted-foreground'}`}>{p.mode === 'activo' ? 'ACTIVO' : 'Simulación'}</span>
                    <span className={`flex items-center gap-1 text-[11px] ${p.enabled ? 'text-primary' : 'text-muted-foreground/60'}`}><Power className="h-3 w-3" /> {p.enabled ? 'habilitado' : 'deshabilitado'}</span>
                  </div>
                  <p className="mt-1 text-xs text-muted-foreground">
                    Si {p.conditions.minLevel ? `nivel ≥ ${p.conditions.minLevel}` : 'cualquier nivel'}
                    {p.conditions.ruleIds?.length ? ` · reglas ${csv(p.conditions.ruleIds)}` : ''}
                    {p.conditions.mitre?.length ? ` · MITRE ${csv(p.conditions.mitre)}` : ''}
                    {p.conditions.agents?.length ? ` · agentes ${csv(p.conditions.agents)}` : ''}
                    {' → '}{p.actions.map((a) => ACTION_LABELS[a.type]).join(' + ')}
                  </p>
                </div>
                <div className="flex items-center gap-1">
                  <Button variant="ghost" size="sm" onClick={() => void test(p)} disabled={busy === p.id} title="Probar">{busy === p.id ? <Loader2 className="h-4 w-4 animate-spin" /> : <FlaskConical className="h-4 w-4" />}</Button>
                  <Button variant="ghost" size="sm" onClick={() => void toggleMode(p)} disabled={busy === p.id} title="Simulación/Activo"><Play className="h-4 w-4" /></Button>
                  <Button variant="ghost" size="sm" onClick={() => void toggleEnabled(p)} disabled={busy === p.id} title="Habilitar/Deshabilitar"><Power className={`h-4 w-4 ${p.enabled ? 'text-primary' : ''}`} /></Button>
                  <Button variant="ghost" size="sm" onClick={() => void remove(p)} disabled={busy === p.id} className="text-destructive-foreground/80" title="Eliminar"><Trash2 className="h-4 w-4" /></Button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Historial de ejecuciones */}
      <div className="glass overflow-hidden rounded-lg">
        <h3 className="flex items-center gap-2 border-b border-border/60 px-4 py-3 text-sm font-semibold"><History className="h-4 w-4" /> Ejecuciones recientes</h3>
        {runs.length === 0 ? (
          <p className="p-6 text-center text-sm text-muted-foreground">Sin ejecuciones aún.</p>
        ) : (
          <div className="max-h-80 overflow-y-auto divide-y divide-border/40">
            {runs.map((r) => (
              <div key={r.id} className="px-4 py-2 text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-medium">{r.playbook_name} <span className="text-muted-foreground">· {r.target}</span></span>
                  <span className="text-muted-foreground">{new Date(r.created_at).toLocaleString('es-CO', { dateStyle: 'short', timeStyle: 'short' })}</span>
                </div>
                <div className="mt-0.5 flex flex-wrap gap-1 text-[11px] text-muted-foreground">
                  <span className={`rounded px-1 ${r.mode === 'activo' ? 'bg-destructive/20' : 'bg-secondary'}`}>{r.mode}</span>
                  {r.actions?.map((a, i) => <span key={i} className="rounded bg-secondary/60 px-1">{a.type}: {a.status}</span>)}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
