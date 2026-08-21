/**
 * Centro de Acción: una sola bandeja priorizada con todo lo que requiere acción
 * (SOAR pendientes, IPs atacantes, identidad, incidentes SLA, endpoints de
 * riesgo) y el botón para resolverlo de un clic. Para operar el SOC con una sola
 * persona (o media) sin recorrer 30 módulos.
 */
import { useCallback, useEffect, useState } from 'react';
import { AxiosError } from 'axios';
import { Inbox, RefreshCw, Loader2, AlertTriangle, CheckCircle2, ShieldAlert, Network, UserCog, Briefcase, Crosshair, Bot } from 'lucide-react';
import { actionCenterApi, type ActionItem, type ActionButton, type Severity } from '@/lib/actionCenter';
import { useAuth } from '@/lib/auth';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

const SEV_COLOR: Record<Severity, string> = { alta: 'destructive', media: 'warn-orange', baja: 'success' };
const SEV_LABEL: Record<Severity, string> = { alta: 'ALTA', media: 'MEDIA', baja: 'BAJA' };
const SRC_ICON: Record<string, typeof Inbox> = { soar: Bot, red: Network, identidad: UserCog, incidente: Briefcase, endpoint: Crosshair };
const SRC_LABEL: Record<string, string> = { soar: 'SOAR', red: 'Red', identidad: 'Identidad', incidente: 'Incidente', endpoint: 'Endpoint' };

export default function ActionCenter() {
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';
  const [items, setItems] = useState<ActionItem[] | null>(null);
  const [counts, setCounts] = useState<Record<Severity, number>>({ alta: 0, media: 0, baja: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<string | null>(null); // `${itemKey}:${kind}`
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const load = useCallback(() => {
    setLoading(true); setError(null);
    actionCenterApi.queue()
      .then((q) => { setItems(q.items); setCounts(q.bySeverity); })
      .catch((e) => setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo cargar el Centro de Acción'))
      .finally(() => setLoading(false));
  }, []);
  useEffect(() => { load(); }, [load]);

  async function run(item: ActionItem, a: ActionButton) {
    setBusy(item.key); setMsg(null);
    try {
      await actionCenterApi.execute(a.kind, a.params);
      setMsg({ ok: true, text: `${a.label} · ${item.subject}` });
      setConfirm(null);
      // Quita el ítem de la cola (optimista) y refresca en segundo plano.
      setItems((prev) => (prev ? prev.filter((x) => x.key !== item.key) : prev));
      setTimeout(load, 800);
    } catch (e) {
      setMsg({ ok: false, text: (e as AxiosError<{ error?: string }>).response?.data?.error ?? 'La acción falló' });
    } finally { setBusy(null); }
  }

  const total = items?.length ?? 0;

  return (
    <div className="mx-auto max-w-5xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="hw-mono flex items-center gap-2 text-2xl font-bold tracking-tight"><Inbox className="h-6 w-6 text-primary" /> Centro de Acción</h1>
          <p className="text-sm text-muted-foreground">Todo lo que requiere una acción, en una sola bandeja priorizada</p>
        </div>
        <Button variant="outline" size="sm" onClick={load} disabled={loading}><RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} /> Actualizar</Button>
      </div>

      <div className="grid gap-3 sm:grid-cols-4">
        <Card><CardContent className="p-4"><p className="text-xs text-muted-foreground">Pendientes</p><p className="text-2xl font-bold tabular-nums">{total}</p></CardContent></Card>
        <Card className={counts.alta > 0 ? 'border-rose-500/40' : ''}><CardContent className="p-4"><p className="text-xs text-muted-foreground">Alta</p><p className="text-2xl font-bold tabular-nums" style={{ color: counts.alta ? 'hsl(var(--destructive))' : undefined }}>{counts.alta}</p></CardContent></Card>
        <Card><CardContent className="p-4"><p className="text-xs text-muted-foreground">Media</p><p className="text-2xl font-bold tabular-nums">{counts.media}</p></CardContent></Card>
        <Card><CardContent className="p-4"><p className="text-xs text-muted-foreground">Baja</p><p className="text-2xl font-bold tabular-nums">{counts.baja}</p></CardContent></Card>
      </div>

      {error && <Card><CardContent className="p-4 text-sm text-amber-700">{error}</CardContent></Card>}
      {msg && <Card className={msg.ok ? 'border-emerald-500/40' : 'border-rose-500/40'}><CardContent className="flex items-center gap-2 p-3 text-sm">{msg.ok ? <CheckCircle2 className="h-4 w-4 text-emerald-600" /> : <AlertTriangle className="h-4 w-4 text-rose-600" />} {msg.text}</CardContent></Card>}

      {loading && !items ? (
        <p className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Reuniendo acciones de todos los módulos…</p>
      ) : total === 0 ? (
        <Card><CardContent className="flex flex-col items-center gap-2 py-16 text-center">
          <CheckCircle2 className="h-10 w-10 text-emerald-500" />
          <p className="text-sm font-semibold">Sin acciones pendientes</p>
          <p className="text-xs text-muted-foreground">Todo bajo control. El sistema seguirá vigilando y traerá aquí lo que requiera tu atención.</p>
        </CardContent></Card>
      ) : (
        <div className="space-y-2.5">
          {items!.map((it) => {
            const c = SEV_COLOR[it.severity];
            const Icon = SRC_ICON[it.source] ?? ShieldAlert;
            return (
              <div key={it.key} className="hw-clip border border-border p-3" style={{ borderLeft: `3px solid hsl(var(--${c}))` }}>
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="hw-mono rounded px-1.5 py-0.5 text-[9px] font-bold" style={{ color: `hsl(var(--${c}))`, background: `hsl(var(--${c}) / .12)` }}>{SEV_LABEL[it.severity]}</span>
                      <span className="hw-mono flex items-center gap-1 rounded bg-secondary px-1.5 py-0.5 text-[9px] uppercase tracking-wider text-muted-foreground"><Icon className="h-3 w-3" /> {SRC_LABEL[it.source] ?? it.source}</span>
                      <span className="text-xs font-semibold">{it.title}</span>
                    </div>
                    <p className="mt-1 truncate text-xs text-foreground/90 hw-mono">{it.subject}</p>
                    <p className="mt-1 text-[11px] leading-snug text-muted-foreground">{it.reason}</p>
                    {it.meta.length > 0 && (
                      <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-0.5 text-[10px] text-muted-foreground/80">
                        {it.meta.map((m, k) => <span key={k}>{m.label}: {m.value}</span>)}
                      </div>
                    )}
                  </div>
                  <div className="flex shrink-0 flex-wrap items-center gap-1.5">
                    {it.actions.map((a) => {
                      const cfKey = `${it.key}:${a.kind}`;
                      const needsAdmin = a.danger; // las destructivas requieren admin en el backend
                      if (needsAdmin && !isAdmin) return <span key={a.kind} className="text-[10px] text-muted-foreground/60">{a.label} (admin)</span>;
                      if (a.danger && confirm !== cfKey) {
                        return <button key={a.kind} disabled={busy === it.key} onClick={() => setConfirm(cfKey)}
                          className="rounded px-2.5 py-1 text-[11px] text-white disabled:opacity-50" style={{ background: 'hsl(var(--destructive))' }}>{a.label}</button>;
                      }
                      if (a.danger && confirm === cfKey) {
                        return (
                          <span key={a.kind} className="flex items-center gap-1">
                            <button disabled={busy === it.key} onClick={() => run(it, a)} className="rounded px-2 py-1 text-[11px] text-white disabled:opacity-50" style={{ background: 'hsl(var(--destructive))' }}>{busy === it.key ? '…' : 'Confirmar'}</button>
                            <button onClick={() => setConfirm(null)} className="rounded border border-input px-2 py-1 text-[11px]">No</button>
                          </span>
                        );
                      }
                      return <button key={a.kind} disabled={busy === it.key} onClick={() => run(it, a)}
                        className="rounded px-2.5 py-1 text-[11px] text-white disabled:opacity-50" style={{ background: 'hsl(var(--primary))' }}>{busy === it.key ? '…' : a.label}</button>;
                    })}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
