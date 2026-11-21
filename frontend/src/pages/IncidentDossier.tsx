/**
 * Dossier de Incidente con IA — expediente auto-escrito de un grupo de actividad:
 * narrativa forense, causa raiz, linea de tiempo real, MITRE y acciones de 1-clic.
 */
import { useCallback, useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import type { AxiosError } from 'axios';
import {
  Sparkles, Loader2, ShieldAlert, ShieldX, Clock, MapPin, Share2, RefreshCw, AlertTriangle, CheckCircle2,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { dossierApi, SEV_COLOR, ACTION_LABEL, type Dossier, type EntType, type DossierAction } from '@/lib/dossier';
import { responseApi } from '@/lib/response';

function Rich({ text }: { text: string }) {
  if (!text) return null;
  return (
    <div className="space-y-1 text-sm leading-relaxed text-foreground/90">
      {text.split('\n').filter((l) => l.trim() !== '').map((line, i) => {
        const bullet = /^\s*[-*]\s+/.test(line);
        const content = line.replace(/^\s*[-*]\s+/, '');
        const parts = content.split('**');
        return (
          <p key={i} className={bullet ? 'flex gap-2' : ''}>
            {bullet && <span className="text-primary">•</span>}
            <span>{parts.map((p, j) => (j % 2 ? <strong key={j}>{p}</strong> : <span key={j}>{p}</span>))}</span>
          </p>
        );
      })}
    </div>
  );
}

const CONF_LABEL: Record<string, string> = { alta: 'Confianza alta', media: 'Confianza media', baja: 'Confianza baja' };

export default function IncidentDossier() {
  const [sp, setSp] = useSearchParams();
  const [type, setType] = useState<EntType>((sp.get('type') as EntType) || 'ip');
  const [value, setValue] = useState<string>(sp.get('value') || '');
  const [dossier, setDossier] = useState<Dossier | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [actionMsg, setActionMsg] = useState<string | null>(null);

  const run = useCallback(async (t: EntType, v: string, force = false) => {
    if (!v.trim()) { setError('Indica una entidad (IP, host, usuario o dominio).'); return; }
    setLoading(true); setError(null); setActionMsg(null);
    try {
      setDossier(await dossierApi.generate(t, v.trim(), { force }));
    } catch (e) {
      setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo generar el dossier.');
      setDossier(null);
    } finally { setLoading(false); }
  }, []);

  // auto-generar si llega por deep link (?type=&value=)
  useEffect(() => {
    const v = sp.get('value'); const t = sp.get('type') as EntType | null;
    if (v && t) run(t, v);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function submit() {
    setSp({ type, value: value.trim() });
    run(type, value, false);
  }

  async function doBlock(a: DossierAction) {
    if (!window.confirm(`¿Bloquear ${a.objetivo} en el SonicWall?`)) return;
    setBusy(a.objetivo);
    try {
      await responseApi.block(a.objetivo, a.motivo || 'Dossier IA', dossier?.incidentId ?? undefined);
      setActionMsg(`IP ${a.objetivo} enviada a bloqueo en el firewall.`);
    } catch (e) {
      setActionMsg((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo bloquear la IP.');
    } finally { setBusy(null); }
  }

  const sevColor = dossier ? SEV_COLOR[dossier.severidad] : undefined;

  return (
    <div className="mx-auto max-w-5xl space-y-5 p-4">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-semibold"><Sparkles className="h-6 w-6 text-primary" /> DOSSIER DE INCIDENTE · IA</h1>
          <p className="text-sm text-muted-foreground">Expediente auto-escrito: narrativa forense, causa raíz, línea de tiempo real y acciones recomendadas.</p>
        </div>
        {dossier && (
          <Button variant="outline" size="sm" disabled={loading} onClick={() => run(dossier.seed.type, dossier.seed.value, true)}>
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />} Regenerar
          </Button>
        )}
      </header>

      {/* Formulario */}
      <div className="flex flex-wrap items-end gap-2 rounded-lg border border-border/60 bg-card/40 p-3">
        <label className="flex flex-col gap-1 text-xs text-muted-foreground">
          Tipo
          <select value={type} onChange={(e) => setType(e.target.value as EntType)} className="rounded-md border border-input bg-background px-2 py-1.5 text-sm">
            <option value="ip">IP</option>
            <option value="host">Host</option>
            <option value="user">Usuario</option>
            <option value="domain">Dominio</option>
          </select>
        </label>
        <label className="flex flex-1 flex-col gap-1 text-xs text-muted-foreground" style={{ minWidth: 220 }}>
          Entidad
          <input value={value} onChange={(e) => setValue(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && submit()}
            placeholder="p.ej. 143.198.74.232 / DGA-ARS / usuario@dominio" className="rounded-md border border-input bg-background px-2 py-1.5 text-sm" />
        </label>
        <Button size="sm" disabled={loading} onClick={submit}>
          {loading ? <><Loader2 className="h-4 w-4 animate-spin" /> Analizando…</> : <><Sparkles className="h-4 w-4" /> Generar dossier</>}
        </Button>
      </div>

      {error && <div className="flex items-center gap-2 rounded-md border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-400"><AlertTriangle className="h-4 w-4" /> {error}</div>}
      {loading && !dossier && <p className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Correlacionando entidades y sintetizando con IA…</p>}

      {dossier && (
        <article className="space-y-5">
          {/* Cabecera del dossier */}
          <div className="rounded-lg border border-border/60 bg-card/40 p-4">
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded px-2 py-0.5 text-xs font-semibold uppercase text-white" style={{ backgroundColor: sevColor }}>{dossier.severidad}</span>
              <span className="rounded border border-border/60 px-2 py-0.5 text-xs text-muted-foreground">{CONF_LABEL[dossier.confianza]}</span>
              <span className="rounded border border-border/60 px-2 py-0.5 text-xs text-muted-foreground">{dossier.stats.alertas} alertas</span>
              {dossier.geo && <span className="flex items-center gap-1 rounded border border-border/60 px-2 py-0.5 text-xs text-muted-foreground"><MapPin className="h-3 w-3" /> {dossier.geo.ciudad ? dossier.geo.ciudad + ', ' : ''}{dossier.geo.pais}</span>}
              <Link to={`/xdr?type=${dossier.seed.type}&value=${encodeURIComponent(dossier.seed.value)}`} className="ml-auto flex items-center gap-1 text-xs text-primary hover:underline"><Share2 className="h-3.5 w-3.5" /> Ver grafo XDR</Link>
            </div>
            <h2 className="mt-2 text-lg font-semibold">{dossier.titulo}</h2>
            <div className="mt-1"><Rich text={dossier.resumen} /></div>
            <p className="mt-2 text-[11px] text-muted-foreground">Semilla: {dossier.seed.type} · {dossier.seed.value} — generado {new Date(dossier.generadoEn).toLocaleString()} · {dossier.modelo}</p>
          </div>

          {/* Acciones recomendadas */}
          {dossier.acciones.length > 0 && (
            <section className="rounded-lg border border-border/60 bg-card/40 p-4">
              <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground"><ShieldAlert className="h-4 w-4 text-primary" /> Acciones recomendadas</h3>
              {actionMsg && <div className="mb-2 flex items-center gap-2 rounded-md border border-primary/30 bg-primary/10 px-3 py-2 text-xs text-primary"><CheckCircle2 className="h-4 w-4" /> {actionMsg}</div>}
              <ol className="space-y-2">
                {dossier.acciones.map((a, i) => (
                  <li key={i} className="flex flex-wrap items-center gap-2 rounded-md border border-border/50 bg-background/40 p-2">
                    <span className="flex h-6 w-6 items-center justify-center rounded-full bg-primary/15 text-xs font-bold text-primary">{i + 1}</span>
                    <div className="flex-1">
                      <p className="text-sm"><b>{ACTION_LABEL[a.tipo]}</b>{a.objetivo ? <> · <span className="font-mono text-xs">{a.objetivo}</span></> : null}</p>
                      <p className="text-xs text-muted-foreground">{a.motivo}</p>
                    </div>
                    {a.tipo === 'block_ip'
                      ? <Button size="sm" variant="destructive" disabled={busy === a.objetivo} onClick={() => doBlock(a)}>{busy === a.objetivo ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldX className="h-4 w-4" />} Bloquear</Button>
                      : <span className="rounded border border-border/60 px-2 py-1 text-[11px] text-muted-foreground">recomendación</span>}
                  </li>
                ))}
              </ol>
            </section>
          )}

          {/* Historia / causa raiz */}
          <div className="grid gap-4 md:grid-cols-3">
            <section className="rounded-lg border border-border/60 bg-card/40 p-4 md:col-span-2">
              <h3 className="mb-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">Análisis forense</h3>
              <Rich text={dossier.historia} />
            </section>
            <div className="space-y-4">
              <section className="rounded-lg border border-border/60 bg-card/40 p-4">
                <h3 className="mb-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">Causa raíz</h3>
                <Rich text={dossier.causaRaiz || '—'} />
              </section>
              {dossier.mitre.length > 0 && (
                <section className="rounded-lg border border-border/60 bg-card/40 p-4">
                  <h3 className="mb-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">MITRE ATT&amp;CK</h3>
                  <div className="flex flex-wrap gap-1.5">
                    {dossier.mitre.map((m) => (
                      <a key={m.id} href={`https://attack.mitre.org/techniques/${m.id.replace('.', '/')}/`} target="_blank" rel="noreferrer"
                        className="rounded border border-primary/30 bg-primary/10 px-2 py-0.5 font-mono text-xs text-primary hover:bg-primary/20" title={m.nombre}>{m.id}</a>
                    ))}
                  </div>
                </section>
              )}
            </div>
          </div>

          {/* Entidades + timeline */}
          <div className="grid gap-4 md:grid-cols-2">
            <section className="rounded-lg border border-border/60 bg-card/40 p-4">
              <h3 className="mb-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">Entidades involucradas</h3>
              <ul className="space-y-1">
                {dossier.entidades.map((e, i) => (
                  <li key={i} className="flex items-center gap-2 text-sm">
                    <span className="w-14 shrink-0 text-xs uppercase text-muted-foreground">{e.tipo}</span>
                    <span className="font-mono text-xs">{e.valor}</span>
                    <span className="text-xs text-muted-foreground">· {e.rol}</span>
                    {e.ioc && <span className="rounded bg-red-500/15 px-1.5 text-[10px] font-semibold text-red-400">IOC</span>}
                  </li>
                ))}
              </ul>
            </section>
            <section className="rounded-lg border border-border/60 bg-card/40 p-4">
              <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground"><Clock className="h-4 w-4" /> Línea de tiempo</h3>
              <ul className="max-h-80 space-y-1 overflow-auto pr-1">
                {dossier.lineaTiempo.map((t, i) => (
                  <li key={i} className="border-l-2 border-border/60 pl-2 text-xs">
                    <span className="text-muted-foreground">{new Date(t.ts).toLocaleString()}</span> · <span className="font-semibold">N{t.nivel}</span> {t.evento}
                  </li>
                ))}
                {dossier.lineaTiempo.length === 0 && <li className="text-xs text-muted-foreground">Sin eventos en la ventana.</li>}
              </ul>
            </section>
          </div>
        </article>
      )}
    </div>
  );
}
