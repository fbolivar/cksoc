/**
 * Postura de correo — autenticación de dominios (SPF / DKIM / DMARC / MX) en vivo
 * desde el DNS, con calificación tipo semáforo y el registro exacto a corregir.
 * Incluye la lectura de reportes agregados DMARC (rua) vía Microsoft Graph.
 */
import { useEffect, useState, useCallback } from 'react';
import { AxiosError } from 'axios';
import { Mail, RefreshCw, Loader2, ShieldCheck, ShieldAlert, Copy, Check as CheckIcon, Inbox, KeyRound, FileText, Server, ArrowUpRight } from 'lucide-react';
import { emailPostureApi, type PostureResponse, type DomainPosture, type Check, type Grade, type DmarcReportSummary } from '@/lib/email-posture';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

const GRADE: Record<Grade, { c: string; label: string }> = {
  ok: { c: 'success', label: 'OK' }, warn: { c: 'warn-orange', label: 'REVISAR' },
  fail: { c: 'destructive', label: 'CRÍTICO' }, missing: { c: 'destructive', label: 'AUSENTE' },
};
const CHECK_ICON: Record<Check['key'], typeof Mail> = { spf: Server, dkim: KeyRound, dmarc: ShieldCheck, mx: Inbox };
const fmt = (n: number) => n.toLocaleString('es-CO');

function CopyBtn({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <button onClick={() => { navigator.clipboard?.writeText(text).then(() => { setDone(true); setTimeout(() => setDone(false), 1500); }); }}
      className="flex items-center gap-1 rounded border border-input px-1.5 py-0.5 text-[10px] text-muted-foreground hover:bg-secondary">
      {done ? <CheckIcon className="h-3 w-3" style={{ color: 'hsl(var(--success))' }} /> : <Copy className="h-3 w-3" />} {done ? 'copiado' : 'copiar'}
    </button>
  );
}

function ScoreRing({ score, grade }: { score: number; grade: Grade }) {
  const c = GRADE[grade].c;
  return (
    <div className="relative flex h-16 w-16 shrink-0 items-center justify-center rounded-full"
      style={{ background: `conic-gradient(hsl(var(--${c})) ${score * 3.6}deg, hsl(var(--secondary)) 0deg)` }}>
      <div className="flex h-12 w-12 items-center justify-center rounded-full bg-card">
        <span className="hw-tabular text-lg font-bold" style={{ color: `hsl(var(--${c}))` }}>{score}</span>
      </div>
    </div>
  );
}

function CheckCard({ c }: { c: Check }) {
  const g = GRADE[c.grade]; const Icon = CHECK_ICON[c.key];
  return (
    <Card><CardContent className="p-4">
      <div className="flex items-center justify-between gap-2">
        <p className="flex items-center gap-2 text-sm font-semibold"><Icon className="h-4 w-4 text-muted-foreground" /> {c.label}</p>
        <span className="hw-mono rounded px-1.5 py-0.5 text-[9px] font-bold" style={{ color: `hsl(var(--${g.c}))`, background: `hsl(var(--${g.c}) / .12)` }}>{g.label}</span>
      </div>
      <p className="mt-1.5 text-xs text-foreground/90">{c.summary}</p>
      {c.value && (
        <pre className="mt-2 overflow-x-auto whitespace-pre-wrap break-all rounded bg-secondary/40 p-2 text-[10.5px] hw-mono text-muted-foreground">{c.value}</pre>
      )}
      {c.findings.length > 0 && (
        <ul className="mt-2 space-y-1">
          {c.findings.map((f, i) => (
            <li key={i} className="flex gap-1.5 text-[11px] leading-snug text-muted-foreground">
              <span className="mt-1 h-1 w-1 shrink-0 rounded-full" style={{ background: `hsl(var(--${g.c}))` }} /> <span>{f}</span>
            </li>
          ))}
        </ul>
      )}
      {c.fix && (
        <div className="mt-2.5 rounded-md border p-2.5" style={{ borderColor: `hsl(var(--${g.c}) / .3)`, background: `hsl(var(--${g.c}) / .05)` }}>
          <p className="text-[11px] font-semibold" style={{ color: `hsl(var(--${g.c}))` }}>➜ {c.fix.title}</p>
          <p className="mt-0.5 text-[10px] text-muted-foreground">Dónde: {c.fix.where}</p>
          {c.fix.record && (
            <div className="mt-1.5 flex items-start gap-2">
              <pre className="flex-1 overflow-x-auto whitespace-pre-wrap break-all rounded bg-card p-1.5 text-[10.5px] hw-mono">{c.fix.record}</pre>
              <CopyBtn text={c.fix.record} />
            </div>
          )}
        </div>
      )}
    </CardContent></Card>
  );
}

function DomainBlock({ d }: { d: DomainPosture }) {
  const g = GRADE[d.grade];
  return (
    <div className="space-y-3">
      <Card><CardContent className="flex items-center gap-4 p-4">
        <ScoreRing score={d.score} grade={d.grade} />
        <div className="min-w-0">
          <p className="hw-mono text-lg font-bold">{d.domain}</p>
          <p className="text-xs" style={{ color: `hsl(var(--${g.c}))` }}>
            {d.grade === 'ok' ? 'Autenticación de correo sólida' : d.grade === 'warn' ? 'Funciona, pero con puntos a endurecer' : 'Expuesto a suplantación — requiere acción'}
          </p>
        </div>
      </CardContent></Card>
      <div className="grid gap-3 md:grid-cols-2">
        {d.checks.map((c) => <CheckCard key={c.key} c={c} />)}
      </div>
    </div>
  );
}

function DmarcReports() {
  const [d, setD] = useState<DmarcReportSummary | null>(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => { emailPostureApi.dmarc(14).then(setD).catch(() => setD(null)).finally(() => setLoading(false)); }, []);

  return (
    <Card><CardContent className="p-4">
      <p className="mb-3 flex items-center gap-2 text-sm font-semibold"><FileText className="h-4 w-4 text-muted-foreground" /> Reportes DMARC agregados · quién envía en tu nombre</p>
      {loading ? (
        <p className="flex items-center gap-2 py-4 text-xs text-muted-foreground"><Loader2 className="h-3.5 w-3.5 animate-spin" /> Consultando…</p>
      ) : !d || !d.ready ? (
        <div>
          <div className="mb-3 flex items-center gap-2 rounded-md border p-3" style={{ borderColor: 'hsl(var(--warn-orange) / .3)', background: 'hsl(var(--warn-orange) / .06)' }}>
            <ShieldAlert className="h-5 w-5 shrink-0" style={{ color: 'hsl(var(--warn-orange))' }} />
            <p className="text-xs text-muted-foreground">Aún no se leen reportes DMARC. Faltan estos prerequisitos (una sola vez); luego este panel muestra automáticamente quién intenta suplantar el dominio.</p>
          </div>
          <ol className="space-y-2">
            {(d?.readiness.missing ?? []).map((m, i) => (
              <li key={i} className="flex gap-2.5 rounded border border-border p-2.5">
                <span className="hw-mono flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-secondary text-[11px] font-bold">{i + 1}</span>
                <div><p className="text-xs font-semibold">{m.step}</p><p className="mt-0.5 text-[11px] text-muted-foreground">{m.detail}</p></div>
              </li>
            ))}
          </ol>
        </div>
      ) : d.reports === 0 ? (
        <p className="py-4 text-xs text-muted-foreground">Prerequisitos listos ✓ — pero aún no llegan reportes al buzón <b className="hw-mono">{d.readiness.mailbox}</b>. Los primeros tardan 1–3 días tras publicar <span className="hw-mono">rua=</span>.</p>
      ) : (
        <>
          <div className="grid gap-3 sm:grid-cols-4">
            <div className="hw-clip border border-border p-3"><p className="text-[10px] uppercase text-muted-foreground">Correo alineado</p><p className="hw-tabular text-xl font-bold" style={{ color: 'hsl(var(--success))' }}>{d.passRate}%</p></div>
            <div className="hw-clip border border-border p-3"><p className="text-[10px] uppercase text-muted-foreground">Mensajes OK</p><p className="hw-tabular text-xl font-bold">{fmt(d.aligned)}</p></div>
            <div className="hw-clip border border-border p-3"><p className="text-[10px] uppercase text-muted-foreground">Fallan DMARC</p><p className="hw-tabular text-xl font-bold" style={{ color: d.failing > 0 ? 'hsl(var(--destructive))' : undefined }}>{fmt(d.failing)}</p></div>
            <div className="hw-clip border border-border p-3"><p className="text-[10px] uppercase text-muted-foreground">Reportes</p><p className="hw-tabular text-xl font-bold">{fmt(d.reports)}</p></div>
          </div>
          <p className="mb-1.5 mt-4 text-[11px] font-medium text-muted-foreground">Orígenes (los que fallan DMARC = posibles suplantadores, primero)</p>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead><tr className="text-left text-[10px] uppercase text-muted-foreground"><th className="py-1">IP origen</th><th>Total</th><th>Pasa</th><th>Falla</th><th>Disposición</th></tr></thead>
              <tbody>
                {d.sources.map((s) => (
                  <tr key={s.ip} className="border-t border-border/50">
                    <td className="py-1 hw-mono">{s.ip}</td><td className="hw-tabular">{fmt(s.count)}</td>
                    <td className="hw-tabular" style={{ color: 'hsl(var(--success))' }}>{fmt(s.pass)}</td>
                    <td className="hw-tabular" style={{ color: s.fail > 0 ? 'hsl(var(--destructive))' : undefined }}>{fmt(s.fail)}</td>
                    <td className="hw-mono text-[10px] text-muted-foreground">{s.disposition}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="mt-2 text-[10px] text-muted-foreground/60">Reporteros: {d.reporters.map((r) => `${r.name} (${r.count})`).join(', ') || '—'}{d.window ? ` · ventana ${d.window.from.slice(0, 10)} a ${d.window.to.slice(0, 10)}` : ''}</p>
        </>
      )}
    </CardContent></Card>
  );
}

export default function EmailPosture() {
  const [data, setData] = useState<PostureResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [domain, setDomain] = useState('');

  const load = useCallback(async (dom?: string) => {
    setLoading(true); setError(null);
    try { setData(await emailPostureApi.posture(dom)); }
    catch (e) { setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo evaluar la postura de correo'); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { load(); }, [load]);

  return (
    <div className="mx-auto max-w-5xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 hw-mono text-2xl font-bold tracking-tight"><Mail className="h-6 w-6 text-neon" /> Postura de correo</h1>
          <p className="text-sm text-muted-foreground">Autenticación del dominio (SPF · DKIM · DMARC · MX) y reportes de suplantación.</p>
        </div>
        <div className="flex items-center gap-2">
          <form onSubmit={(e) => { e.preventDefault(); load(domain.trim() || undefined); }} className="flex items-center gap-1.5">
            <input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="otro dominio…"
              className="w-40 rounded-md border border-input bg-transparent px-2.5 py-1.5 text-xs outline-none focus:border-primary" />
            <Button type="submit" variant="outline" size="sm" disabled={loading}><ArrowUpRight className="h-4 w-4" /></Button>
          </form>
          <Button variant="outline" size="sm" onClick={() => load(domain.trim() || undefined)} disabled={loading}><RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} /></Button>
        </div>
      </div>

      {error && <Card><CardContent className="p-4 text-sm text-amber-700">{error}</CardContent></Card>}

      {loading && !data ? (
        <p className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Consultando el DNS del dominio…</p>
      ) : data && (
        <>
          {data.domains.map((d) => <DomainBlock key={d.domain} d={d} />)}
          <DmarcReports />
          <div className="rounded-md border border-border bg-secondary/20 p-3">
            <p className="text-[11px] leading-relaxed text-muted-foreground">
              <b>Cómo se interpreta:</b> <b>SPF</b> dice qué servidores pueden enviar como tu dominio; <b>DKIM</b> firma cada correo con una llave; <b>DMARC</b> le dice al receptor qué hacer si SPF/DKIM fallan y a dónde reportar. La meta es <span className="hw-mono">DMARC p=reject</span> con SPF <span className="hw-mono">-all</span> y DKIM activo. Estos registros se editan en el <b>DNS del dominio</b> (no en el SIEM).
            </p>
          </div>
          <p className="text-center text-[11px] text-muted-foreground/60">Consulta DNS en vivo · {new Date(data.generatedAt).toLocaleTimeString('es-CO')}</p>
        </>
      )}
    </div>
  );
}
