/**
 * Gestión de Detecciones: reglas más ruidosas (candidatas a falso positivo) y
 * administración de supresiones de FP sin editar XML a mano. Crear/borrar una
 * supresión modifica el ruleset y reinicia el manager de Wazuh (~15 s).
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { AxiosError } from 'axios';
import { SlidersHorizontal, RefreshCw, Loader2, VolumeX, Trash2, X, AlertTriangle, ShieldOff } from 'lucide-react';
import { detectionApi, type NoisyRule, type Suppression } from '@/lib/detection';
import { useAuth } from '@/lib/auth';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { RangeTabs, RANGE_24_7_30 } from '@/components/shared/RangeTabs';

function levelColor(level: number): string {
  if (level >= 12) return '#dc2626';
  if (level >= 8) return '#ea580c';
  if (level >= 5) return '#ca8a04';
  return '#6b7280';
}

export default function Detection() {
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';

  const [range, setRange] = useState('24h');
  const [noisy, setNoisy] = useState<NoisyRule[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [fields, setFields] = useState<string[]>([]);
  const [suppressions, setSuppressions] = useState<Suppression[] | null>(null);
  const [supErr, setSupErr] = useState<string | null>(null);
  const [removing, setRemoving] = useState<number | null>(null);
  const [modalFor, setModalFor] = useState<NoisyRule | null>(null);

  const seq = useRef(0);
  const loadNoisy = useCallback(async (r: string) => {
    const my = ++seq.current;
    setLoading(true); setError(null);
    try {
      const rules = await detectionApi.noisy(r);
      if (my === seq.current) setNoisy(rules);
    } catch (e) {
      if (my === seq.current) { setNoisy(null); setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudieron cargar las reglas'); }
    } finally {
      if (my === seq.current) setLoading(false);
    }
  }, []);

  const loadSuppressions = useCallback(async () => {
    try {
      const data = await detectionApi.suppressions();
      setFields(data.fields); setSuppressions(data.suppressions); setSupErr(null);
    } catch (e) {
      setSupErr((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudieron cargar las supresiones');
    }
  }, []);

  useEffect(() => { void loadNoisy(range); }, [range, loadNoisy]);
  useEffect(() => { void loadSuppressions(); }, [loadSuppressions]);

  async function remove(id: number) {
    if (!confirm('¿Eliminar esta supresión? Se reactivará la regla y el manager se reiniciará (~15 s).')) return;
    setRemoving(id);
    try {
      await detectionApi.removeSuppression(id);
      await loadSuppressions();
    } catch (e) {
      setSupErr((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo eliminar');
    } finally {
      setRemoving(null);
    }
  }

  const suppressedIds = new Set((suppressions ?? []).map((s) => s.targetRuleId));

  return (
    <div className="mx-auto max-w-6xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
            <SlidersHorizontal className="h-6 w-6 text-neon" /> Gestión de Detecciones
          </h1>
          <p className="text-sm text-muted-foreground">Reglas más ruidosas y supresión de falsos positivos</p>
        </div>
        <div className="flex items-center gap-2">
          <RangeTabs value={range} onChange={setRange} options={RANGE_24_7_30} />
          <Button variant="outline" size="sm" onClick={() => void loadNoisy(range)} disabled={loading}>
            <RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} />
          </Button>
        </div>
      </div>

      {error && <Card><CardContent className="p-4 text-sm text-amber-700">{error}</CardContent></Card>}

      {/* Reglas ruidosas */}
      <Card>
        <CardContent className="p-0">
          <div className="border-b border-border/60 px-4 py-2.5 text-sm font-semibold">Reglas que más disparan · {range}</div>
          {loading && !noisy ? (
            <p className="flex items-center justify-center gap-2 py-12 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Cargando…</p>
          ) : !noisy || noisy.length === 0 ? (
            <p className="py-10 text-center text-sm text-muted-foreground">Sin datos en el rango.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border/60 text-left text-xs text-muted-foreground">
                    <th className="px-4 py-2 font-medium">Regla</th>
                    <th className="px-2 py-2 font-medium">Nivel</th>
                    <th className="px-2 py-2 font-medium">Descripción</th>
                    <th className="px-2 py-2 font-medium text-right">Eventos</th>
                    {isAdmin && <th className="px-2 py-2 font-medium text-right">Acción</th>}
                  </tr>
                </thead>
                <tbody>
                  {noisy.map((r) => (
                    <tr key={r.ruleId} className="border-b border-border/30 last:border-0 hover:bg-secondary/40">
                      <td className="whitespace-nowrap px-4 py-2 font-mono text-xs">
                        {r.ruleId}
                        {suppressedIds.has(r.ruleId) && <span className="ml-2 inline-flex items-center gap-1 rounded bg-amber-500/15 px-1.5 py-0.5 text-[10px] text-amber-600"><ShieldOff className="h-3 w-3" /> con supresión</span>}
                      </td>
                      <td className="px-2 py-2"><span className="text-xs font-semibold" style={{ color: levelColor(r.level) }}>{r.level}</span></td>
                      <td className="max-w-md px-2 py-2"><span className="block truncate text-xs">{r.description}</span></td>
                      <td className="px-2 py-2 text-right font-semibold tabular-nums">{r.count.toLocaleString('es-CO')}</td>
                      {isAdmin && (
                        <td className="px-2 py-2 text-right">
                          <Button size="sm" variant="outline" onClick={() => setModalFor(r)} title="Crear una excepción para esta regla">
                            <VolumeX className="h-4 w-4" /> Silenciar
                          </Button>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Supresiones activas */}
      <Card>
        <CardContent className="p-0">
          <div className="flex items-center justify-between border-b border-border/60 px-4 py-2.5">
            <span className="text-sm font-semibold">Supresiones activas (excepciones de falso positivo)</span>
            <span className="text-xs text-muted-foreground">{suppressions?.length ?? 0}</span>
          </div>
          {supErr && <p className="p-4 text-sm text-amber-700">{supErr}</p>}
          {!suppressions ? (
            <p className="flex items-center gap-2 p-4 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Cargando…</p>
          ) : suppressions.length === 0 ? (
            <p className="py-8 text-center text-sm text-muted-foreground">No hay supresiones. Usa "Silenciar" en una regla ruidosa para crear una.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border/60 text-left text-xs text-muted-foreground">
                    <th className="px-4 py-2 font-medium">Regla</th>
                    <th className="px-2 py-2 font-medium">Cuando el campo</th>
                    <th className="px-2 py-2 font-medium">Contiene</th>
                    <th className="px-2 py-2 font-medium">Nota</th>
                    {isAdmin && <th className="px-2 py-2 font-medium text-right">Acción</th>}
                  </tr>
                </thead>
                <tbody>
                  {suppressions.map((s) => (
                    <tr key={s.id} className="border-b border-border/30 last:border-0 hover:bg-secondary/40">
                      <td className="whitespace-nowrap px-4 py-2 font-mono text-xs">{s.targetRuleId}</td>
                      <td className="px-2 py-2 font-mono text-[11px] text-muted-foreground">{s.field}</td>
                      <td className="px-2 py-2 font-mono text-xs">{s.value}</td>
                      <td className="px-2 py-2 text-xs text-muted-foreground">{s.comment || '—'}</td>
                      {isAdmin && (
                        <td className="px-2 py-2 text-right">
                          <Button size="sm" variant="ghost" onClick={() => void remove(s.id)} disabled={removing === s.id} title="Eliminar supresión">
                            {removing === s.id ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4 text-destructive" />}
                          </Button>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {modalFor && (
        <SuppressModal rule={modalFor} fields={fields} onClose={() => setModalFor(null)}
          onCreated={() => { setModalFor(null); void loadSuppressions(); }} />
      )}
    </div>
  );
}

function SuppressModal({ rule, fields, onClose, onCreated }: { rule: NoisyRule; fields: string[]; onClose: () => void; onCreated: () => void }) {
  const [field, setField] = useState(fields[0] ?? 'srcip');
  const [value, setValue] = useState('');
  const [comment, setComment] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function create() {
    if (value.trim().length < 1) { setErr('Indica el valor a suprimir'); return; }
    setBusy(true); setErr(null);
    try {
      await detectionApi.addSuppression({ targetRuleId: rule.ruleId, field, value: value.trim(), comment: comment.trim() });
      onCreated();
    } catch (e) {
      setErr((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo crear la supresión');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div className="w-full max-w-lg rounded-lg border border-border/70 bg-card shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between border-b border-border/60 px-5 py-3">
          <h3 className="font-semibold">Silenciar regla <span className="font-mono text-sm">{rule.ruleId}</span></h3>
          <Button variant="ghost" size="icon" onClick={onClose}><X className="h-4 w-4" /></Button>
        </div>
        <div className="space-y-3 p-5">
          <p className="text-xs text-muted-foreground">{rule.description}</p>
          <div className="space-y-1.5">
            <label className="text-xs text-muted-foreground">Cuando el campo…</label>
            <select value={field} onChange={(e) => setField(e.target.value)} className="h-9 w-full rounded-md border border-input bg-background/60 px-2 text-sm">
              {fields.map((f) => <option key={f} value={f}>{f}</option>)}
            </select>
          </div>
          <div className="space-y-1.5">
            <label className="text-xs text-muted-foreground">…contiene el valor</label>
            <Input value={value} onChange={(e) => setValue(e.target.value)} placeholder="p. ej. 192.168.0.25 o CONSECUTIVO DE DOLIBAR" />
          </div>
          <div className="space-y-1.5">
            <label className="text-xs text-muted-foreground">Nota (opcional)</label>
            <Input value={comment} onChange={(e) => setComment(e.target.value)} placeholder="motivo de la excepción" />
          </div>
          {err && <p className="text-sm text-destructive">{err}</p>}
          <div className="flex items-start gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 p-2.5 text-[11px] text-amber-700">
            <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            Al aplicar se crea una excepción (regla nivel 1) y se <strong>reinicia el manager de Wazuh (~15 s)</strong>. Los eventos que coincidan dejarán de alertar.
          </div>
          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={onClose} disabled={busy}>Cancelar</Button>
            <Button onClick={() => void create()} disabled={busy}>
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <VolumeX className="h-4 w-4" />} Crear supresión
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
