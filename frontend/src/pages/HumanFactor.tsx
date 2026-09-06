/**
 * Factor humano: resultados de campañas de phishing / concienciación. Registra
 * campañas y muestra las métricas que alimentan el dominio "factor humano" del
 * Resumen Ejecutivo (tasa de clics, reporte por usuarios, % capacitados).
 */
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { AxiosError } from 'axios';
import { Users, RefreshCw, Loader2, Plus, Trash2, Lightbulb, UserSearch, Target, KeyRound, ArrowRight } from 'lucide-react';
import { phishingApi, type Campaign, type HumanFactor } from '@/lib/phishing';
import { useAuth } from '@/lib/auth';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

function pct(n: number) { return `${n}%`; }
function todayInput(): string { const d = new Date(); const p = (x: number) => String(x).padStart(2, '0'); return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`; }

function Kpi({ label, value, color, sub }: { label: string; value: string; color?: string; sub?: string }) {
  return (
    <Card><CardContent className="p-4">
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className="text-2xl font-bold tabular-nums" style={color ? { color } : undefined}>{value}</p>
      {sub && <p className="text-[11px] text-muted-foreground/70">{sub}</p>}
    </CardContent></Card>
  );
}

export default function HumanFactor() {
  const { user } = useAuth();
  const canManage = user?.role === 'admin' || user?.role === 'analista';
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [metrics, setMetrics] = useState<HumanFactor | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [name, setName] = useState('');
  const [runDate, setRunDate] = useState(todayInput());
  const [sent, setSent] = useState('');
  const [clicked, setClicked] = useState('');
  const [reported, setReported] = useState('');
  const [trainedPct, setTrainedPct] = useState('');
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);

  async function load() {
    setLoading(true); setError(null);
    try { const d = await phishingApi.get(); setCampaigns(d.campaigns); setMetrics(d.metrics); }
    catch (e) { setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudieron cargar las campañas'); }
    finally { setLoading(false); }
  }
  useEffect(() => { load(); }, []);

  async function create() {
    if (!name.trim() || !sent) { setError('Nombre y enviados son obligatorios'); return; }
    setBusy(true); setError(null);
    try {
      await phishingApi.create({ name, runDate, sent: Number(sent), clicked: Number(clicked) || 0, reported: Number(reported) || 0, trainedPct: Number(trainedPct) || 0, note: note.trim() || undefined });
      setName(''); setSent(''); setClicked(''); setReported(''); setTrainedPct(''); setNote('');
      await load();
    } catch (e) { setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo registrar'); }
    finally { setBusy(false); }
  }
  async function remove(id: string) {
    if (!confirm('¿Borrar esta campaña?')) return;
    await phishingApi.remove(id).catch(() => undefined);
    await load();
  }

  const clickColor = (r: number) => r <= 5 ? 'hsl(var(--success))' : r <= 15 ? 'hsl(var(--warn-orange))' : 'hsl(var(--destructive))';

  return (
    <div className="mx-auto max-w-5xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 hw-mono text-2xl font-bold tracking-tight"><Users className="h-6 w-6 text-neon" /> Factor humano</h1>
          <p className="text-sm text-muted-foreground">Campañas de phishing y concienciación · alimenta el Resumen Ejecutivo</p>
        </div>
        <Button variant="outline" size="sm" onClick={load} disabled={loading}><RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} /> Actualizar</Button>
      </div>

      {error && <Card><CardContent className="p-4 text-sm text-amber-700">{error}</CardContent></Card>}

      {/* KPIs */}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Kpi label="Tasa de clics en phishing" value={metrics ? pct(metrics.clickRate) : '—'} color={metrics ? clickColor(metrics.clickRate) : undefined} sub="menos es mejor" />
        <Kpi label="Reportado por usuarios" value={metrics ? pct(metrics.reportRate) : '—'} sub="más es mejor" />
        <Kpi label="% empleados capacitados" value={metrics ? pct(metrics.trainedPct) : '—'} />
        <Kpi label="Postura factor humano" value={metrics ? `${metrics.posture}/100` : '—'} sub={metrics ? `${metrics.campaigns} campañas · ${metrics.totalSent} envíos` : 'sin campañas'} />
      </div>

      {/* Estado vacío honesto: sin campañas no hay postura; se explica y se enlaza al riesgo humano REAL. */}
      {!metrics && !loading && (
        <Card className="border-amber-500/30"><CardContent className="space-y-3 p-4">
          <p className="flex items-center gap-2 text-sm font-semibold"><Lightbulb className="h-4 w-4 text-amber-500" /> Aún sin datos de simulación</p>
          <p className="text-xs leading-relaxed text-muted-foreground">
            Este módulo mide el riesgo ante phishing con <b>simulaciones</b>: se envía un correo señuelo y se mide quién hace clic y quién lo reporta.
            No se alimenta de la telemetría automática — necesita que corras una campaña y registres el resultado abajo. Por eso los indicadores están en «—»: no es un error, es que aún no hay campañas.
          </p>
          <div className="rounded-md border border-border bg-secondary/20 p-3">
            <p className="mb-2 text-[11px] font-medium text-muted-foreground">Mientras tanto, el factor humano de comportamiento <b>real</b> (usuarios riesgosos por su conducta y sus credenciales) sí lo tienes en vivo:</p>
            <div className="flex flex-wrap gap-2">
              <Link to="/comportamiento" className="inline-flex items-center gap-1.5 rounded-md border border-input px-2.5 py-1.5 text-xs hover:border-primary/40 hover:text-primary"><UserSearch className="h-3.5 w-3.5" /> Comportamiento (UEBA) <ArrowRight className="h-3 w-3" /></Link>
              <Link to="/riesgo-entidad" className="inline-flex items-center gap-1.5 rounded-md border border-input px-2.5 py-1.5 text-xs hover:border-primary/40 hover:text-primary"><Target className="h-3.5 w-3.5" /> Riesgo por entidad <ArrowRight className="h-3 w-3" /></Link>
              <Link to="/exposicion-credenciales" className="inline-flex items-center gap-1.5 rounded-md border border-input px-2.5 py-1.5 text-xs hover:border-primary/40 hover:text-primary"><KeyRound className="h-3.5 w-3.5" /> Exposición de credenciales <ArrowRight className="h-3 w-3" /></Link>
            </div>
          </div>
          <p className="text-[11px] text-muted-foreground/80">
            <b>Para empezar:</b> corre una simulación de phishing (con <span className="hw-mono">GoPhish</span> gratuito, o el <span className="hw-mono">Attack Simulation Training</span> de Microsoft 365 si tienen la licencia) y registra <b>enviados / clics / reportes</b> abajo. Con la primera campaña este panel cobra vida.
          </p>
        </CardContent></Card>
      )}

      {/* Registrar campaña */}
      {canManage && (
        <Card><CardContent className="space-y-3 p-4">
          <p className="text-sm font-semibold">Registrar campaña</p>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            <div className="space-y-1 lg:col-span-2"><label className="text-xs text-muted-foreground">Nombre</label><Input value={name} onChange={(e) => setName(e.target.value)} placeholder="p. ej. Simulacro Q3 - Facturación falsa" /></div>
            <div className="space-y-1"><label className="text-xs text-muted-foreground">Fecha</label><Input type="date" value={runDate} onChange={(e) => setRunDate(e.target.value)} /></div>
            <div className="space-y-1"><label className="text-xs text-muted-foreground">Enviados</label><Input type="number" value={sent} onChange={(e) => setSent(e.target.value)} placeholder="0" /></div>
            <div className="space-y-1"><label className="text-xs text-muted-foreground">Hicieron clic</label><Input type="number" value={clicked} onChange={(e) => setClicked(e.target.value)} placeholder="0" /></div>
            <div className="space-y-1"><label className="text-xs text-muted-foreground">Reportaron</label><Input type="number" value={reported} onChange={(e) => setReported(e.target.value)} placeholder="0" /></div>
            <div className="space-y-1"><label className="text-xs text-muted-foreground">% capacitados</label><Input type="number" value={trainedPct} onChange={(e) => setTrainedPct(e.target.value)} placeholder="0" /></div>
            <div className="space-y-1 lg:col-span-2"><label className="text-xs text-muted-foreground">Nota (opcional)</label><Input value={note} onChange={(e) => setNote(e.target.value)} /></div>
          </div>
          <div className="flex justify-end"><Button onClick={create} disabled={busy}>{busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />} Registrar</Button></div>
        </CardContent></Card>
      )}

      {/* Lista */}
      <Card><CardContent className="p-0">
        <div className="border-b border-border/60 px-4 py-2.5 text-sm font-semibold">Campañas registradas</div>
        {loading && campaigns.length === 0 ? (
          <p className="flex items-center gap-2 p-4 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Cargando…</p>
        ) : campaigns.length === 0 ? (
          <p className="py-8 text-center text-sm text-muted-foreground">Sin campañas. {canManage ? 'Registra una arriba para llenar el dominio de factor humano.' : ''}</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="border-b border-border/60 text-left text-xs text-muted-foreground">
                <th className="px-4 py-2 font-medium">Campaña</th><th className="px-2 py-2 font-medium">Fecha</th>
                <th className="px-2 py-2 font-medium text-right">Enviados</th><th className="px-2 py-2 font-medium text-right">Clic</th>
                <th className="px-2 py-2 font-medium text-right">Reportó</th><th className="px-2 py-2 font-medium text-right">Capacit.</th>
                {canManage && <th className="px-2 py-2" />}
              </tr></thead>
              <tbody>
                {campaigns.map((c) => {
                  const cr = c.sent ? Math.round((c.clicked / c.sent) * 1000) / 10 : 0;
                  return (
                    <tr key={c.id} className="border-b border-border/30 last:border-0 hover:bg-secondary/40">
                      <td className="px-4 py-2"><span className="font-medium">{c.name}</span>{c.note ? <span className="block text-[11px] text-muted-foreground">{c.note}</span> : null}</td>
                      <td className="px-2 py-2 text-xs text-muted-foreground">{new Date(c.run_date).toLocaleDateString('es-CO')}</td>
                      <td className="px-2 py-2 text-right tabular-nums">{c.sent}</td>
                      <td className="px-2 py-2 text-right tabular-nums" style={{ color: clickColor(cr) }}>{c.clicked} <span className="text-[10px] text-muted-foreground">({cr}%)</span></td>
                      <td className="px-2 py-2 text-right tabular-nums">{c.reported}</td>
                      <td className="px-2 py-2 text-right tabular-nums">{c.trained_pct}%</td>
                      {canManage && <td className="px-2 py-2 text-right"><Button size="sm" variant="ghost" onClick={() => remove(c.id)}><Trash2 className="h-4 w-4 text-destructive" /></Button></td>}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </CardContent></Card>
    </div>
  );
}
