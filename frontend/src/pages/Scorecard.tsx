import { useEffect, useState } from 'react';
import { ShieldCheck, RefreshCw, AlertTriangle, CheckCircle2 } from 'lucide-react';
import { scorecardApi, gradeColor, type ScorecardData, type ScoreCategory } from '@/lib/scorecard';

function GradeRing({ grade, score, size = 132 }: { grade: string; score: number; size?: number }) {
  const color = gradeColor(grade as never);
  const r = size / 2 - 8;
  const circ = 2 * Math.PI * r;
  const off = circ * (1 - score / 100);
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="currentColor" strokeWidth={8} className="text-secondary/60" />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={8} strokeLinecap="round" strokeDasharray={circ} strokeDashoffset={off} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-4xl font-black" style={{ color }}>{grade}</span>
        <span className="text-xs text-muted-foreground">{score}/100</span>
      </div>
    </div>
  );
}

function CatCard({ c }: { c: ScoreCategory }) {
  const color = gradeColor(c.grade);
  const nd = c.score == null;
  return (
    <div className="glass rounded-lg p-4">
      <div className="mb-2 flex items-center justify-between gap-2">
        <span className="text-sm font-semibold">{c.label}</span>
        <span className="flex items-center gap-2">
          <span className="text-[10px] text-muted-foreground">peso {c.weight}%</span>
          <span className="rounded px-2 py-0.5 text-xs font-bold" style={{ color, background: `${color}1f` }}>{nd ? 'n/d' : c.grade}</span>
        </span>
      </div>
      <div className="mb-1 flex items-center justify-between text-[11px] text-muted-foreground">
        <span>{c.resumen}</span>
        {!nd && <span className="hw-tabular font-medium" style={{ color }}>{c.score}</span>}
      </div>
      <div className="mb-3 h-1.5 w-full overflow-hidden rounded-full bg-secondary/60">
        {!nd && <div className="h-full" style={{ width: `${c.score}%`, background: color }} />}
      </div>
      <ul className="space-y-1">
        {c.hallazgos.map((h, i) => (
          <li key={i} className="flex items-start gap-1.5 text-[11px] text-muted-foreground">
            {h.startsWith('Sin ') || h.includes('correcto') ? <CheckCircle2 className="mt-0.5 h-3 w-3 shrink-0 text-emerald-500" /> : <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0 text-amber-500" />}
            <span>{h}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default function Scorecard() {
  const [d, setD] = useState<ScorecardData | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function load(refresh = false) {
    setLoading(true); setErr(null);
    try { setD(refresh ? await scorecardApi.refresh() : await scorecardApi.get()); }
    catch { setErr('No se pudo construir el scorecard.'); }
    finally { setLoading(false); }
  }
  useEffect(() => { void load(false); }, []);

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-bold"><ShieldCheck className="h-5 w-5 text-brand" /> Scorecard de Exposición Externa</h1>
          <p className="text-sm text-muted-foreground">Calificación A–F de lo que un atacante ve del cliente desde afuera: superficie, correo, credenciales, suplantación y ransomware.</p>
        </div>
        <button onClick={() => void load(true)} disabled={loading} className="inline-flex items-center gap-1 rounded-lg border border-border bg-secondary/40 px-3 py-1.5 text-xs hover:bg-secondary disabled:opacity-50">
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} /> Recalcular
        </button>
      </div>

      {err && <div className="flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-2 text-xs text-amber-600"><AlertTriangle className="h-4 w-4" /> {err}</div>}

      {d && (
        <>
          <div className="glass flex flex-wrap items-center gap-6 rounded-lg p-5">
            <GradeRing grade={d.grade} score={d.score} />
            <div className="min-w-[220px] flex-1">
              <div className="text-xs uppercase tracking-wide text-muted-foreground">Exposición externa general</div>
              <div className="mt-1 text-lg font-semibold">{d.resumenEjecutivo}</div>
              <div className="mt-3 flex flex-wrap gap-2">
                {d.categorias.map((c) => (
                  <span key={c.key} className="rounded-full border border-border bg-secondary/40 px-2.5 py-1 text-[11px]">
                    {c.label}: <b style={{ color: gradeColor(c.grade) }}>{c.score == null ? 'n/d' : c.grade}</b>
                  </span>
                ))}
              </div>
              <p className="mt-3 text-[10px] text-muted-foreground/60">Generado {new Date(d.generatedAt).toLocaleString('es-CO')} · agrega ASM, postura de correo, credenciales, DRP y ransomware.</p>
            </div>
          </div>

          <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
            {d.categorias.map((c) => <CatCard key={c.key} c={c} />)}
          </div>
        </>
      )}
      {loading && !d && <div className="glass h-40 animate-pulse rounded-lg" />}
    </div>
  );
}
