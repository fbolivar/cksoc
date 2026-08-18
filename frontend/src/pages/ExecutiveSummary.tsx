/**
 * Resumen Ejecutivo (unifica el antiguo "Resumen" y "Riesgo · Ejecutivo").
 * Una sola vista de dirección: índice de postura compuesto (semáforo global) +
 * los 6 dominios de riesgo del negocio, cada uno con su pregunta, postura /100,
 * KPIs con semáforo y enlace directo a su módulo de detalle.
 * Fuente única: riskApi.board(). Auto-refresco cada 60 s.
 */
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  ShieldCheck, RefreshCw, HelpCircle, ChevronRight,
  Crosshair, Bug, UserSearch, GraduationCap, DatabaseBackup, Scale,
} from 'lucide-react';
import { riskApi, STATUS_DOT, LEVEL_COLOR, type RiskBoard, type Domain, type Status } from '@/lib/risk';

const STATUS_LABEL: Record<Status, string> = { good: 'Saludable', warn: 'Atención', bad: 'Crítico', pending: 'Sin fuente' };

// Cada dominio de riesgo enlaza a su módulo de detalle (lo que aportaba el Resumen).
const DOMAIN_LINK: Record<string, { to: string; icon: typeof Bug } | undefined> = {
  deteccion: { to: '/alertas', icon: Crosshair },
  exposicion: { to: '/vulnerabilidades', icon: Bug },
  identidades: { to: '/comportamiento', icon: UserSearch },
  factor_humano: { to: '/cumplimiento', icon: GraduationCap },
  resiliencia: { to: '/respaldos', icon: DatabaseBackup },
  gobierno: { to: '/cumplimiento', icon: Scale },
};

function PostureBar({ posture, status }: { posture: number | null; status: Status }) {
  if (posture === null) return <div className="h-1.5 w-full rounded-full bg-secondary" />;
  const color = status === 'good' ? 'bg-primary' : status === 'warn' ? 'bg-warn' : 'bg-destructive';
  return (
    <div className="h-1.5 w-full overflow-hidden rounded-full bg-secondary">
      <div className={`h-full ${color}`} style={{ width: `${posture}%` }} />
    </div>
  );
}

function DomainCard({ d }: { d: Domain }) {
  const link = DOMAIN_LINK[d.key];
  const Icon = link?.icon;
  const border = d.status === 'good' ? 'border-l-primary' : d.status === 'warn' ? 'border-l-warn' : d.status === 'bad' ? 'border-l-destructive' : 'border-l-muted-foreground/30';

  const body = (
    <>
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <h3 className="flex items-center gap-2 font-semibold">
            {Icon && <Icon className="h-4 w-4 shrink-0 text-neon" />}
            {d.title}
            {link && <ChevronRight className="h-4 w-4 text-muted-foreground/40 transition-transform group-hover:translate-x-0.5" />}
          </h3>
          <p className="mt-0.5 text-xs italic text-muted-foreground">{d.businessQuestion}</p>
        </div>
        <div className="text-right">
          <span className={`text-lg font-bold ${d.posture === null ? 'text-muted-foreground/50' : d.status === 'good' ? 'text-primary' : d.status === 'warn' ? 'text-warn' : 'text-destructive'}`}>
            {d.posture === null ? '—' : `${d.posture}`}
          </span>
          {d.posture !== null && <span className="text-[10px] text-muted-foreground">/100</span>}
        </div>
      </div>
      <div className="my-3"><PostureBar posture={d.posture} status={d.status} /></div>
      <ul className="space-y-1.5">
        {d.kpis.map((k, i) => (
          <li key={i} className="flex items-center justify-between gap-2 text-sm">
            <span className="flex items-center gap-2 text-muted-foreground">
              <span className={`h-2 w-2 shrink-0 rounded-full ${STATUS_DOT[k.status]}`} />
              {k.label}
              {k.note && (<span title={k.note}><HelpCircle className="h-3 w-3 text-muted-foreground/50" /></span>)}
            </span>
            <span className={`font-medium ${k.source === 'pending' ? 'text-muted-foreground/50' : k.status === 'bad' ? 'text-destructive' : k.status === 'warn' ? 'text-warn' : 'text-foreground'}`}>
              {k.value}
            </span>
          </li>
        ))}
      </ul>
    </>
  );

  const cls = `glass block rounded-lg border-l-4 ${border} p-4`;
  return link
    ? <Link to={link.to} className={`group transition-colors hover:border-primary/40 ${cls}`} title={`Ver detalle: ${d.title}`}>{body}</Link>
    : <div className={cls}>{body}</div>;
}

export default function ExecutiveSummary() {
  const [board, setBoard] = useState<RiskBoard | null>(null);
  const [loading, setLoading] = useState(true);

  const load = () => {
    setLoading(true);
    riskApi.board().then(setBoard).catch(() => setBoard(null)).finally(() => setLoading(false));
  };
  useEffect(() => {
    load();
    const t = setInterval(load, 60_000);
    return () => clearInterval(t);
  }, []);

  return (
    <div className="mx-auto max-w-6xl space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="flex items-center gap-2 hw-mono text-2xl font-bold tracking-tight"><ShieldCheck className="h-6 w-6 text-brand" /> Resumen Ejecutivo</h1>
          <p className="text-sm text-muted-foreground">Postura del SOC traducida a riesgo del negocio · una sola vista</p>
        </div>
        <button onClick={load} className="text-muted-foreground hover:text-foreground" title="Refrescar"><RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} /></button>
      </div>

      {loading && !board ? (
        <div className="glass rounded-lg p-10 text-center text-sm text-muted-foreground">Calculando postura de riesgo…</div>
      ) : !board ? (
        <div className="glass rounded-lg p-10 text-center text-sm text-muted-foreground">Sin datos</div>
      ) : (
        <>
          {/* Índice compuesto = semáforo/postura global */}
          <div className="glass rounded-lg p-5">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div>
                <p className="text-xs uppercase tracking-wide text-muted-foreground">Postura de seguridad (índice compuesto)</p>
                <p className={`mt-1 text-4xl font-bold ${LEVEL_COLOR[board.index.level]}`}>
                  {board.index.score}<span className="text-lg text-muted-foreground">/100</span>
                </p>
                <p className={`text-sm font-medium ${LEVEL_COLOR[board.index.level]}`}>{board.index.label}</p>
              </div>
              <div className="max-w-sm text-right">
                <p className="text-sm italic text-muted-foreground">{board.overallQuestion}</p>
                <p className="mt-2 text-[11px] text-muted-foreground/70">
                  {board.index.measuredDomains} de 6 dominios con datos · el factor humano requiere fuentes externas (phishing/LMS)
                </p>
              </div>
            </div>
            <div className="mt-4 h-2 w-full overflow-hidden rounded-full bg-secondary">
              <div className={`h-full ${board.index.score >= 80 ? 'bg-primary' : board.index.score >= 60 ? 'bg-warn' : board.index.score >= 40 ? 'bg-orange-400' : 'bg-destructive'}`} style={{ width: `${board.index.score}%` }} />
            </div>
          </div>

          {/* Dominios (clicables a su módulo de detalle) */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            {board.domains.map((d) => <DomainCard key={d.key} d={d} />)}
          </div>

          {/* leyenda */}
          <div className="flex flex-wrap items-center gap-4 text-[11px] text-muted-foreground">
            {(['good', 'warn', 'bad', 'pending'] as Status[]).map((s) => (
              <span key={s} className="flex items-center gap-1.5"><span className={`h-2 w-2 rounded-full ${STATUS_DOT[s]}`} />{STATUS_LABEL[s]}</span>
            ))}
            <span className="ml-auto">Actualizado {new Date(board.generatedAt).toLocaleString('es-CO', { dateStyle: 'short', timeStyle: 'short' })} · cada 60 s</span>
          </div>
        </>
      )}
    </div>
  );
}
