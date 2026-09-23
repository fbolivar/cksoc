/**
 * SOAR — Respuesta automatizada. Reglas que, ante alertas que cumplen una
 * condición, ejecutan una acción (bloquear/aislar/crear incidente) de forma
 * automática o previa aprobación. Con salvaguardas: aprobación, dry-run, cooldown.
 */
import { useCallback, useEffect, useState } from 'react';
import { AxiosError } from 'axios';
import { Zap, RefreshCw, Loader2, Plus, Trash2, X, Play, Check, Ban, ShieldCheck } from 'lucide-react';
import { soarApi, type AutomationRule, type AutomationEvent, type TriggerType, type ActionType, type Mode } from '@/lib/soar';
import { useAuth } from '@/lib/auth';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

const TRIGGER_LABEL: Record<TriggerType, string> = {
  ioc_ip_match: 'IP coincide con un IOC',
  rule_level: 'Alertas de nivel ≥ X',
  rule_id: 'Regla específica dispara',
};
const ACTION_LABEL: Record<ActionType, string> = {
  block_ip: 'Bloquear IP (SonicWall)',
  isolate_host: 'Aislar host (Velociraptor)',
  create_incident: 'Crear incidente',
  disable_ad_user: 'Deshabilitar cuenta AD (LDAP)',
  disable_m365_user: 'Deshabilitar cuenta M365 (Graph)',
};
const STATUS_COLOR: Record<string, string> = {
  pending: '#d97706', executed: '#059669', failed: '#dc2626', skipped: '#6b7280', rejected: '#6b7280',
};

export default function Soar() {
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';
  const [rules, setRules] = useState<AutomationRule[] | null>(null);
  const [events, setEvents] = useState<AutomationEvent[] | null>(null);
  const [pending, setPending] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [showAdd, setShowAdd] = useState(false);
  const [acting, setActing] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const [r, e] = await Promise.all([soarApi.rules(), soarApi.events()]);
      setRules(r); setEvents(e.events); setPending(e.pending);
    } catch (err) {
      setError((err as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo cargar SOAR');
    }
  }, []);
  useEffect(() => { void load(); }, [load]);

  async function runNow() {
    setBusy(true);
    try { await soarApi.run(); await load(); }
    catch (err) { setError((err as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo ejecutar'); }
    finally { setBusy(false); }
  }
  async function resolve(id: string, decision: 'approve' | 'reject') {
    setActing(id);
    try { await soarApi.resolve(id, decision); await load(); }
    catch (err) { setError((err as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo resolver'); }
    finally { setActing(null); }
  }
  async function toggle(r: AutomationRule) {
    await soarApi.updateRule(r.id, { enabled: !r.enabled }).catch(() => undefined);
    await load();
  }
  async function del(id: string) {
    if (!confirm('¿Eliminar esta regla de automatización?')) return;
    await soarApi.removeRule(id).catch(() => undefined);
    await load();
  }

  const pendingEvents = (events ?? []).filter((e) => e.status === 'pending');
  const history = (events ?? []).filter((e) => e.status !== 'pending').slice(0, 40);

  return (
    <div className="mx-auto max-w-6xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 hw-mono text-2xl font-bold tracking-tight">
            <Zap className="h-6 w-6 text-neon" /> SOAR · Respuesta automatizada
          </h1>
          <p className="text-sm text-muted-foreground">Reglas que actúan solas (o con tu aprobación) ante amenazas</p>
        </div>
        {isAdmin && (
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => void runNow()} disabled={busy}>
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />} Evaluar ahora
            </Button>
            <Button size="sm" onClick={() => setShowAdd(true)}><Plus className="h-4 w-4" /> Nueva regla</Button>
          </div>
        )}
      </div>

      {error && <Card><CardContent className="p-4 text-sm text-amber-700">{error}</CardContent></Card>}

      {/* Cola de aprobación */}
      {pendingEvents.length > 0 && (
        <Card className="border-amber-500/40">
          <CardContent className="p-0">
            <div className="flex items-center gap-2 border-b border-border/60 px-4 py-2.5">
              <ShieldCheck className="h-4 w-4 text-amber-600" />
              <span className="text-sm font-semibold">Pendientes de aprobación</span>
              <span className="rounded-full bg-amber-500/20 px-2 py-0.5 text-xs font-semibold text-amber-700">{pending}</span>
            </div>
            <div className="divide-y divide-border/30">
              {pendingEvents.map((e) => (
                <div key={e.id} className="flex flex-wrap items-center justify-between gap-2 px-4 py-2.5">
                  <div className="min-w-0 text-sm">
                    <span className="font-medium">{ACTION_LABEL[e.action]}</span> sobre <span className="font-mono text-xs">{e.entity}</span>
                    <span className="ml-2 text-xs text-muted-foreground">· regla “{e.rule_name}” · {typeof e.detail?.count === 'number' ? `${e.detail.count} alertas` : ''}</span>
                  </div>
                  {isAdmin && (
                    <div className="flex items-center gap-2">
                      <Button size="sm" variant="destructive" onClick={() => void resolve(e.id, 'reject')} disabled={acting === e.id}><Ban className="h-4 w-4" /> Rechazar</Button>
                      <Button size="sm" onClick={() => void resolve(e.id, 'approve')} disabled={acting === e.id}>
                        {acting === e.id ? <Loader2 className="h-4 w-4 animate-spin" /> : <Check className="h-4 w-4" />} Aprobar y ejecutar
                      </Button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Reglas */}
      <Card>
        <CardContent className="p-0">
          <div className="flex items-center justify-between border-b border-border/60 px-4 py-2.5">
            <span className="text-sm font-semibold">Reglas de automatización</span>
            <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => void load()}><RefreshCw className="h-4 w-4" /></Button>
          </div>
          {!rules ? (
            <p className="flex items-center gap-2 p-4 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Cargando…</p>
          ) : rules.length === 0 ? (
            <p className="py-8 text-center text-sm text-muted-foreground">Sin reglas. Crea una con "Nueva regla".</p>
          ) : (
            <div className="divide-y divide-border/30">
              {rules.map((r) => (
                <div key={r.id} className="flex flex-wrap items-center justify-between gap-2 px-4 py-3">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-medium">{r.name}</span>
                      <span className={`rounded px-1.5 py-0.5 text-[10px] font-semibold ${r.enabled ? 'bg-emerald-500/15 text-emerald-600' : 'bg-secondary text-muted-foreground'}`}>{r.enabled ? 'activa' : 'inactiva'}</span>
                      <span className="rounded bg-secondary px-1.5 py-0.5 text-[10px] text-muted-foreground">{r.mode === 'auto' ? 'automático' : 'aprobación'}</span>
                      {r.dry_run && <span className="rounded bg-amber-500/15 px-1.5 py-0.5 text-[10px] text-amber-600">dry-run</span>}
                    </div>
                    <p className="mt-0.5 text-xs text-muted-foreground">
                      Si {TRIGGER_LABEL[r.trigger_type]}{r.trigger_type === 'rule_level' ? ` (≥${r.trigger_config.minLevel}${r.trigger_config.group ? `, ${r.trigger_config.group}` : ''})` : r.trigger_type === 'rule_id' ? ` (${r.trigger_config.ruleId})` : ''} → <strong className="text-foreground">{ACTION_LABEL[r.action]}</strong> · cooldown {r.cooldown_min}m · {r.trigger_count} disparos
                    </p>
                  </div>
                  {isAdmin && (
                    <div className="flex items-center gap-2">
                      <Button size="sm" variant="outline" onClick={() => void toggle(r)}>{r.enabled ? 'Desactivar' : 'Activar'}</Button>
                      <Button size="sm" variant="ghost" onClick={() => void del(r.id)}><Trash2 className="h-4 w-4 text-destructive" /></Button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Historial */}
      <Card>
        <CardContent className="p-0">
          <div className="border-b border-border/60 px-4 py-2.5 text-sm font-semibold">Historial de ejecuciones</div>
          {!history || history.length === 0 ? (
            <p className="py-8 text-center text-sm text-muted-foreground">Sin ejecuciones aún.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border/60 text-left text-xs text-muted-foreground">
                    <th className="px-4 py-2 font-medium">Fecha</th>
                    <th className="px-2 py-2 font-medium">Regla</th>
                    <th className="px-2 py-2 font-medium">Acción</th>
                    <th className="px-2 py-2 font-medium">Entidad</th>
                    <th className="px-2 py-2 font-medium">Estado</th>
                  </tr>
                </thead>
                <tbody>
                  {history.map((e) => (
                    <tr key={e.id} className="border-b border-border/30 last:border-0">
                      <td className="whitespace-nowrap px-4 py-2 text-xs text-muted-foreground">{new Date(e.created_at).toLocaleString('es-CO')}</td>
                      <td className="px-2 py-2 text-xs">{e.rule_name}</td>
                      <td className="px-2 py-2 text-xs">{ACTION_LABEL[e.action]}</td>
                      <td className="px-2 py-2 font-mono text-[11px]">{e.entity}</td>
                      <td className="px-2 py-2 text-xs">
                        <span style={{ color: STATUS_COLOR[e.status] ?? '#6b7280' }}>{e.status}</span>
                        {e.status === 'failed' && e.detail?.error ? <span className="ml-1 text-[10px] text-destructive">({String(e.detail.error)})</span> : null}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {showAdd && <RuleModal onClose={() => setShowAdd(false)} onCreated={() => { setShowAdd(false); void load(); }} />}
    </div>
  );
}

function RuleModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [name, setName] = useState('');
  const [triggerType, setTriggerType] = useState<TriggerType>('ioc_ip_match');
  const [minLevel, setMinLevel] = useState(10);
  const [group, setGroup] = useState('');
  const [ruleId, setRuleId] = useState('');
  const [action, setAction] = useState<ActionType>('block_ip');
  const [mode, setMode] = useState<Mode>('approval');
  const [dryRun, setDryRun] = useState(true);
  const [cooldown, setCooldown] = useState(60);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function create() {
    if (name.trim().length < 3) { setErr('Nombre muy corto'); return; }
    const trigger_config = triggerType === 'rule_level' ? { minLevel, group: group.trim() || undefined }
      : triggerType === 'rule_id' ? { ruleId: ruleId.trim() } : {};
    setBusy(true); setErr(null);
    try {
      await soarApi.createRule({ name: name.trim(), trigger_type: triggerType, trigger_config, action, mode, dry_run: dryRun, cooldown_min: cooldown });
      onCreated();
    } catch (e) {
      setErr((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo crear');
    } finally { setBusy(false); }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div className="w-full max-w-lg rounded-lg border border-border/70 bg-card shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between border-b border-border/60 px-5 py-3">
          <h3 className="font-semibold">Nueva regla de automatización</h3>
          <Button variant="ghost" size="icon" onClick={onClose}><X className="h-4 w-4" /></Button>
        </div>
        <div className="space-y-3 p-5">
          <div className="space-y-1.5">
            <label className="text-xs text-muted-foreground">Nombre</label>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="p. ej. Bloquear IPs de IOC con actividad" />
          </div>
          <div className="space-y-1.5">
            <label className="text-xs text-muted-foreground">Disparador (SI…)</label>
            <select value={triggerType} onChange={(e) => setTriggerType(e.target.value as TriggerType)} className="h-9 w-full rounded-md border border-input bg-background/60 px-2 text-sm">
              <option value="ioc_ip_match">La IP de origen coincide con un IOC conocido</option>
              <option value="rule_level">Hay alertas de nivel ≥ X</option>
              <option value="rule_id">Dispara una regla específica</option>
            </select>
          </div>
          {triggerType === 'rule_level' && (
            <div className="flex gap-2">
              <div className="flex-1 space-y-1.5"><label className="text-xs text-muted-foreground">Nivel mínimo</label>
                <Input type="number" value={minLevel} onChange={(e) => setMinLevel(Number(e.target.value))} /></div>
              <div className="flex-1 space-y-1.5"><label className="text-xs text-muted-foreground">Grupo (opcional)</label>
                <Input value={group} onChange={(e) => setGroup(e.target.value)} placeholder="p. ej. authentication_failed" /></div>
            </div>
          )}
          {triggerType === 'rule_id' && (
            <div className="space-y-1.5"><label className="text-xs text-muted-foreground">ID de regla</label>
              <Input value={ruleId} onChange={(e) => setRuleId(e.target.value)} placeholder="p. ej. 100215" /></div>
          )}
          <div className="space-y-1.5">
            <label className="text-xs text-muted-foreground">Acción (ENTONCES…)</label>
            <select value={action} onChange={(e) => setAction(e.target.value as ActionType)} className="h-9 w-full rounded-md border border-input bg-background/60 px-2 text-sm">
              <option value="block_ip">Bloquear la IP en SonicWall</option>
              <option value="isolate_host">Aislar el host en Velociraptor</option>
              <option value="create_incident">Crear un incidente</option>
              <option value="disable_ad_user">Deshabilitar la cuenta en AD (LDAP)</option>
              <option value="disable_m365_user">Deshabilitar la cuenta en M365 (Graph)</option>
            </select>
            {(action === 'disable_ad_user' || action === 'disable_m365_user') && (
              <p className="rounded-md border border-amber-500/30 bg-amber-500/10 p-2 text-[11px] text-amber-700">
                ⚠️ Acción sobre <b>usuario</b> (campo data.srcuser de la alerta). Requiere configurar {action === 'disable_ad_user' ? 'LDAP (AD)' : 'Microsoft Graph (M365)'} en el .env; si no, la ejecución quedará registrada como "no configurado".
              </p>
            )}
          </div>
          <div className="flex gap-2">
            <div className="flex-1 space-y-1.5"><label className="text-xs text-muted-foreground">Modo</label>
              <select value={mode} onChange={(e) => setMode(e.target.value as Mode)} className="h-9 w-full rounded-md border border-input bg-background/60 px-2 text-sm">
                <option value="approval">Requiere aprobación</option>
                <option value="auto">Automático</option>
              </select></div>
            <div className="flex-1 space-y-1.5"><label className="text-xs text-muted-foreground">Cooldown (min)</label>
              <Input type="number" value={cooldown} onChange={(e) => setCooldown(Number(e.target.value))} /></div>
          </div>
          <label className="flex items-center gap-2 text-xs text-muted-foreground">
            <input type="checkbox" checked={dryRun} onChange={(e) => setDryRun(e.target.checked)} /> Dry-run (solo registra, no ejecuta) — recomendado para probar
          </label>
          {err && <p className="text-sm text-destructive">{err}</p>}
          {mode === 'auto' && !dryRun && (
            <p className="rounded-md border border-amber-500/30 bg-amber-500/10 p-2 text-[11px] text-amber-700">⚠️ Modo automático sin dry-run: la acción se ejecutará sola. El bloqueo respeta la lista blanca; aislar corta la red del host.</p>
          )}
          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={onClose} disabled={busy}>Cancelar</Button>
            <Button onClick={() => void create()} disabled={busy}>{busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />} Crear regla</Button>
          </div>
        </div>
      </div>
    </div>
  );
}
