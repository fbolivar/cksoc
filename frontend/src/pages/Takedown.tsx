import { useEffect, useState } from 'react';
import { Scale, RefreshCw, AlertTriangle, Copy, Check, Mail, Loader2 } from 'lucide-react';
import { takedownApi, type Candidate, type TakedownPackage } from '@/lib/takedown';

function CopyBtn({ text, label }: { text: string; label?: string }) {
  const [ok, setOk] = useState(false);
  return (
    <button
      onClick={() => { navigator.clipboard?.writeText(text).then(() => { setOk(true); setTimeout(() => setOk(false), 1500); }).catch(() => undefined); }}
      className="inline-flex items-center gap-1 rounded border border-border bg-secondary/40 px-2 py-0.5 text-[10px] hover:bg-secondary"
    >
      {ok ? <Check className="h-3 w-3 text-emerald-500" /> : <Copy className="h-3 w-3" />} {label ?? (ok ? 'Copiado' : 'Copiar')}
    </button>
  );
}

const sevCls = (s: string): string => s === 'critica' ? 'text-red-500' : s === 'alta' ? 'text-orange-400' : s === 'media' ? 'text-amber-500' : 'text-slate-400';

export default function Takedown() {
  const [cands, setCands] = useState<Candidate[]>([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [sel, setSel] = useState<string | null>(null);
  const [pkg, setPkg] = useState<TakedownPackage | null>(null);
  const [gen, setGen] = useState(false);

  async function load() {
    setLoading(true); setErr(null);
    try { setCands(await takedownApi.candidates()); }
    catch { setErr('No se pudieron cargar los dominios candidatos (DRP).'); }
    finally { setLoading(false); }
  }
  useEffect(() => { void load(); }, []);

  async function generate(domain: string) {
    setSel(domain); setGen(true); setPkg(null);
    try { setPkg(await takedownApi.generate(domain)); }
    catch { setErr('No se pudo generar el paquete.'); }
    finally { setGen(false); }
  }

  const mailto = pkg
    ? `mailto:${pkg.recipients.map((r) => r.email).join(',')}?subject=${encodeURIComponent(pkg.subject)}&body=${encodeURIComponent(pkg.body)}`
    : '#';

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-bold"><Scale className="h-5 w-5 text-brand" /> Generador de Takedown</h1>
          <p className="text-sm text-muted-foreground">Arma la solicitud de retiro para los dominios de suplantación detectados por el DRP. Resuelve el contacto de abuso (registrador y hosting) y redacta el correo con la evidencia.</p>
        </div>
        <button onClick={() => void load()} disabled={loading} className="inline-flex items-center gap-1 rounded-lg border border-border bg-secondary/40 px-3 py-1.5 text-xs hover:bg-secondary disabled:opacity-50">
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} /> Actualizar
        </button>
      </div>

      <div className="flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-2 text-[11px] text-amber-700">
        <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
        HexWatch <b>no envía</b> el takedown: genera el borrador para que lo revises y lo remitas desde tu correo de abuso. Verifica siempre los datos antes de enviar.
      </div>

      {err && <div className="flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-2 text-xs text-amber-600"><AlertTriangle className="h-4 w-4" /> {err}</div>}

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="glass rounded-lg p-4">
          <p className="mb-3 text-sm font-semibold">Dominios candidatos ({cands.length})</p>
          {cands.length === 0 ? (
            <p className="py-6 text-center text-xs text-muted-foreground">Sin dominios de suplantación abiertos en el DRP.</p>
          ) : (
            <div className="max-h-[480px] space-y-1.5 overflow-y-auto">
              {cands.map((c) => (
                <div key={c.id} className={`rounded border px-2.5 py-2 ${sel === c.domain ? 'border-brand bg-secondary/40' : 'border-border bg-secondary/20'}`}>
                  <div className="flex items-center justify-between gap-2">
                    <span className="hw-mono truncate text-xs font-medium">{c.domain}</span>
                    <button onClick={() => void generate(c.domain)} disabled={gen} className="inline-flex items-center gap-1 rounded bg-brand px-2 py-0.5 text-[10px] font-semibold text-white hover:opacity-90 disabled:opacity-50">
                      {gen && sel === c.domain ? <Loader2 className="h-3 w-3 animate-spin" /> : <Scale className="h-3 w-3" />} Generar
                    </button>
                  </div>
                  <p className="mt-0.5 text-[10px] text-muted-foreground">
                    suplanta <b>{c.brand}</b> · {c.tecnica} · <span className={sevCls(c.severidad)}>{c.severidad}</span>
                    {c.mx && <span className="ml-1 rounded bg-red-500/15 px-1 text-red-500">MX: puede enviar correo</span>}
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="glass rounded-lg p-4">
          <p className="mb-3 text-sm font-semibold">Paquete de solicitud</p>
          {!pkg ? (
            <p className="py-6 text-center text-xs text-muted-foreground">Elige un dominio y pulsa “Generar”.</p>
          ) : (
            <div className="space-y-3 text-xs">
              <div className="rounded border border-border bg-secondary/20 px-3 py-2 text-[11px] text-muted-foreground">{pkg.aviso}</div>
              <div>
                <div className="mb-1 flex items-center justify-between"><span className="font-semibold">Destinatarios</span>{pkg.recipients.length > 0 && <CopyBtn text={pkg.recipients.map((r) => r.email).join(', ')} />}</div>
                {pkg.recipients.length === 0 ? <p className="text-muted-foreground">Sin contacto de abuso por RDAP — consultar WHOIS manual.</p> : (
                  <ul className="space-y-0.5">{pkg.recipients.map((r, i) => <li key={i} className="hw-mono"><span className="text-muted-foreground">{r.tipo}:</span> {r.email}</li>)}</ul>
                )}
              </div>
              <div>
                <div className="mb-1 flex items-center justify-between"><span className="font-semibold">Asunto</span><CopyBtn text={pkg.subject} /></div>
                <p className="hw-mono rounded bg-secondary/30 px-2 py-1">{pkg.subject}</p>
              </div>
              <div>
                <div className="mb-1 flex items-center justify-between"><span className="font-semibold">Mensaje</span><CopyBtn text={pkg.body} /></div>
                <textarea readOnly value={pkg.body} className="h-56 w-full rounded border border-border bg-secondary/30 px-2 py-1 font-mono text-[10px]" />
              </div>
              {pkg.recipients.length > 0 && (
                <a href={mailto} className="inline-flex items-center gap-1 rounded-lg bg-brand px-3 py-1.5 text-xs font-semibold text-white hover:opacity-90"><Mail className="h-3.5 w-3.5" /> Abrir en el correo</a>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
