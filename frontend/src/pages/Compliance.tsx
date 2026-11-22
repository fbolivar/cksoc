/**
 * Cumplimiento normativo: controles ejercidos por las alertas de seguridad, orientados
 * a los marcos que le aplican al cliente (Ley 1581, ISO 27001, GDPR). Mide cobertura de
 * monitoreo, no un puntaje de cumplimiento.
 */
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { AxiosError } from 'axios';
import { Scale, RefreshCw, Loader2, ExternalLink, Info, ShieldCheck, FileDown } from 'lucide-react';
import {
  complianceApi, FRAMEWORKS, PRIORIDAD_COLOR, APLICA_META, CONTROL_DESC,
  type ComplianceData,
} from '@/lib/compliance';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { RangeTabs } from '@/components/shared/RangeTabs';

type Range = '7d' | '30d' | '90d';
const HOURS: Record<Range, number> = { '7d': 168, '30d': 720, '90d': 2160 };

export default function Compliance() {
  const [range, setRange] = useState<Range>('30d');
  const [data, setData] = useState<ComplianceData | null>(null);
  const [tab, setTab] = useState(FRAMEWORKS[0].key);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [downloading, setDownloading] = useState(false);

  async function descargar() {
    setDownloading(true); setError(null);
    try { await complianceApi.downloadReport(HOURS[range]); }
    catch { setError('No se pudo generar el informe PDF'); }
    finally { setDownloading(false); }
  }

  async function load(r: Range) {
    setLoading(true); setError(null);
    try { setData(await complianceApi.get(HOURS[r])); }
    catch (e) { setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo cargar cumplimiento'); }
    finally { setLoading(false); }
  }
  useEffect(() => { load(range); }, [range]);

  const meta = FRAMEWORKS.find((f) => f.key === tab)!;
  const fw = data?.frameworks[tab];
  const maxCount = Math.max(1, ...(fw?.controles ?? []).map((c) => c.count));
  const cobertura = fw ? Math.min(100, Math.round((fw.controlesCubiertos / meta.catalogo) * 100)) : 0;
  const coberturaColor = cobertura >= 66 ? '#22c55e' : cobertura >= 33 ? '#eab308' : '#f59e0b';

  return (
    <div className="mx-auto max-w-6xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 hw-mono text-2xl font-bold tracking-tight">
            <Scale className="h-6 w-6 text-neon" /> Cumplimiento normativo
          </h1>
          <p className="text-sm text-muted-foreground">
            Cobertura de monitoreo por marco, priorizada según lo que le aplica al cliente (no es un puntaje de cumplimiento)
          </p>
        </div>
        <div className="flex items-center gap-2">
          <RangeTabs value={range} onChange={setRange}
            options={[{ value: '7d', label: '7 días' }, { value: '30d', label: '30 días' }, { value: '90d', label: '90 días' }]} />
          <Button variant="outline" size="sm" onClick={() => load(range)} disabled={loading}>
            <RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} /> Actualizar
          </Button>
          <Button size="sm" onClick={descargar} disabled={downloading || loading}>
            {downloading ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileDown className="h-4 w-4" />} Informe PDF
          </Button>
        </div>
      </div>

      {error && <Card><CardContent className="p-4 text-sm text-amber-700">{error}</CardContent></Card>}

      {/* Pestañas de marcos: aplicables primero, los que no aplican al final (atenuados) */}
      <div className="flex flex-wrap gap-1 border-b border-border/60">
        {FRAMEWORKS.map((f) => {
          const ap = APLICA_META[f.aplica];
          const active = tab === f.key;
          return (
            <button key={f.key} onClick={() => setTab(f.key)}
              className={`flex items-center gap-2 px-3.5 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors ${
                active ? 'border-primary text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground'
              } ${f.aplica === 'no' && !active ? 'opacity-55' : ''}`}>
              {f.label}
              <span className="rounded-full px-1.5 py-0.5 text-[9px] font-semibold"
                style={{ background: `${ap.color}22`, color: ap.color }}>
                {ap.label}
              </span>
            </button>
          );
        })}
      </div>

      {loading && !data ? (
        <p className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" /> Cargando cumplimiento…
        </p>
      ) : fw && (
        <>
          {/* Contexto + KPIs */}
          <div className="flex flex-wrap items-start gap-3 rounded-lg border border-border/60 bg-secondary/30 p-4">
            <Info className="mt-0.5 h-4 w-4 shrink-0 text-neon" />
            <div className="min-w-0 flex-1 text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <b>{meta.label}</b>
                <span className="rounded-full px-1.5 py-0.5 text-[10px] font-semibold"
                  style={{ background: `${APLICA_META[meta.aplica].color}22`, color: APLICA_META[meta.aplica].color }}>
                  {APLICA_META[meta.aplica].label}
                </span>
                <span className="rounded-full px-1.5 py-0.5 text-[10px] font-semibold"
                  style={{ background: `${PRIORIDAD_COLOR[meta.prioridad]}22`, color: PRIORIDAD_COLOR[meta.prioridad] }}>
                  Prioridad {meta.prioridad}
                </span>
                {meta.derivado && (
                  <span className="rounded-full bg-neon/15 px-1.5 py-0.5 text-[10px] font-semibold text-neon">derivado por crosswalk</span>
                )}
                {meta.ref(tab) && (
                  <a href={meta.ref(tab)!} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-neon hover:underline">
                    referencia <ExternalLink className="h-3 w-3" />
                  </a>
                )}
              </div>
              <p className="mt-1 text-muted-foreground">{meta.contexto}</p>
              {meta.nota && <p className="mt-1.5 text-[12px] text-muted-foreground/90"><b className="text-muted-foreground">Alcance:</b> {meta.nota}</p>}
            </div>
            <div className="flex gap-6 text-right">
              <div>
                {meta.aplica === 'no'
                  ? <p className="text-2xl font-semibold tabular-nums text-muted-foreground/50">—</p>
                  : <p className="text-2xl font-semibold tabular-nums" style={{ color: coberturaColor }}>{cobertura}%</p>}
                <p className="text-[11px] text-muted-foreground">cobertura técnica</p>
              </div>
              <div><p className="text-2xl font-semibold tabular-nums">{fw.controlesCubiertos}</p><p className="text-[11px] text-muted-foreground">de {meta.catalogo} controles</p></div>
              <div><p className="text-2xl font-semibold tabular-nums">{fw.total.toLocaleString('es-CO')}</p><p className="text-[11px] text-muted-foreground">alertas de seguridad</p></div>
            </div>
          </div>

          {/* Reencuadre honesto + enlace a postura real (SCA) */}
          <div className="flex flex-wrap items-center gap-2.5 rounded-md border border-border/60 bg-secondary/20 p-3 text-[11px] leading-relaxed text-muted-foreground">
            <Info className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
            <p className="min-w-0 flex-1">
              Esto mide <b>cobertura de monitoreo</b> (cuántos controles técnicos del marco están vigilados por alertas reales; se excluye el ruido benigno del SO/red). <b>No es un puntaje de cumplimiento</b>: un conteo alto significa "hay actividad monitoreada", no "cumple". La <b>postura de configuración real</b> (¿estás configurado al estándar?) se mide en Hardening CIS con aprobado/fallido por control.
            </p>
            <Link to="/sca" className="inline-flex shrink-0 items-center gap-1 rounded-md border border-neon/40 bg-neon/10 px-2.5 py-1 text-xs font-medium text-neon hover:bg-neon/20">
              <ShieldCheck className="h-3.5 w-3.5" /> Ver postura CIS (SCA)
            </Link>
          </div>

          {/* Controles ejercidos */}
          <Card>
            <CardContent className="p-4">
              {fw.controles.length === 0 ? (
                <p className="py-8 text-center text-sm text-muted-foreground">Sin eventos mapeados a este marco en el periodo.</p>
              ) : (
                <div className="space-y-2.5">
                  {fw.controles.map((c) => (
                    <div key={c.id} className="flex items-center gap-3">
                      <span className="w-28 shrink-0 font-mono text-xs text-neon" title={c.src ?? undefined}>{c.id}</span>
                      <div className="min-w-0 flex-1">
                        <div className="mb-1 flex items-center justify-between gap-2">
                          <span className="flex min-w-0 items-center gap-1.5 truncate text-sm">
                            {c.level >= 8 && <span className="shrink-0 rounded px-1 py-0.5 text-[9px] font-bold text-white" style={{ background: c.level >= 12 ? '#dc2626' : '#f59e0b' }} title={`Máx. severidad nivel ${c.level}`}>N{c.level}</span>}
                            <span className="truncate" title={c.src ?? undefined}>{CONTROL_DESC[c.id] ?? 'Control del marco'}</span>
                          </span>
                          <span className="shrink-0 tabular-nums text-xs text-muted-foreground">{c.count.toLocaleString('es-CO')}</span>
                        </div>
                        <div className="h-1.5 w-full overflow-hidden rounded-full bg-secondary">
                          <div className="h-full bg-primary/70" style={{ width: `${(c.count / maxCount) * 100}%` }} />
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          <p className="text-[11px] text-muted-foreground/60">
            {meta.derivado
              ? 'Marco derivado por crosswalk desde los controles técnicos que Wazuh etiqueta (NIST/GDPR). La capa legal y organizacional se gestiona por fuera del SIEM.'
              : 'Cada control refleja cuántos eventos del periodo aportan evidencia a ese requisito. No es una certificación: es la cobertura de monitoreo mapeada automáticamente por Wazuh.'}
          </p>
        </>
      )}
    </div>
  );
}
