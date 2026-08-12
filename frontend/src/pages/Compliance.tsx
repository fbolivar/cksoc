/**
 * Cumplimiento normativo: controles de NIST 800-53, GDPR, TSC (SOC 2), PCI DSS e
 * HIPAA ejercidos por las alertas, priorizados segun el contexto de PNNC.
 */
import { useEffect, useState } from 'react';
import { AxiosError } from 'axios';
import { Scale, RefreshCw, Loader2, ExternalLink, Info } from 'lucide-react';
import {
  complianceApi, FRAMEWORKS, PRIORIDAD_COLOR, CONTROL_DESC,
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

  return (
    <div className="mx-auto max-w-6xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
            <Scale className="h-6 w-6 text-neon" /> Cumplimiento normativo
          </h1>
          <p className="text-sm text-muted-foreground">
            Controles de los marcos regulatorios ejercidos por el monitoreo, priorizados para HexWatch
          </p>
        </div>
        <div className="flex items-center gap-2">
          <RangeTabs value={range} onChange={setRange}
            options={[{ value: '7d', label: '7 días' }, { value: '30d', label: '30 días' }, { value: '90d', label: '90 días' }]} />
          <Button variant="outline" size="sm" onClick={() => load(range)} disabled={loading}>
            <RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} /> Actualizar
          </Button>
        </div>
      </div>

      {error && <Card><CardContent className="p-4 text-sm text-amber-700">{error}</CardContent></Card>}

      {/* Pestañas de marcos (orden por prioridad) */}
      <div className="flex flex-wrap gap-1 border-b border-border/60">
        {FRAMEWORKS.map((f) => (
          <button key={f.key} onClick={() => setTab(f.key)}
            className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors ${
              tab === f.key ? 'border-primary text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground'
            }`}>
            {f.label}
            <span className="rounded-full px-1.5 py-0.5 text-[9px] font-semibold"
              style={{ background: `${PRIORIDAD_COLOR[f.prioridad]}22`, color: PRIORIDAD_COLOR[f.prioridad] }}>
              {f.prioridad}
            </span>
          </button>
        ))}
      </div>

      {loading && !data ? (
        <p className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" /> Cargando cumplimiento…
        </p>
      ) : fw && (
        <>
          {/* Contexto + KPIs */}
          <div className="flex items-start gap-3 rounded-lg border border-border/60 bg-secondary/30 p-4">
            <Info className="mt-0.5 h-4 w-4 shrink-0 text-neon" />
            <div className="flex-1 text-sm">
              <div className="flex items-center gap-2">
                <b>{meta.label}</b>
                <span className="rounded-full px-1.5 py-0.5 text-[10px] font-semibold"
                  style={{ background: `${PRIORIDAD_COLOR[meta.prioridad]}22`, color: PRIORIDAD_COLOR[meta.prioridad] }}>
                  Prioridad {meta.prioridad}
                </span>
                {meta.ref(tab) && (
                  <a href={meta.ref(tab)!} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-neon hover:underline">
                    referencia <ExternalLink className="h-3 w-3" />
                  </a>
                )}
              </div>
              <p className="mt-1 text-muted-foreground">{meta.contexto}</p>
            </div>
            <div className="flex gap-6 text-right">
              <div><p className="text-2xl font-semibold tabular-nums">{fw.total.toLocaleString('es-CO')}</p><p className="text-[11px] text-muted-foreground">eventos</p></div>
              <div><p className="text-2xl font-semibold tabular-nums">{fw.controles.length}</p><p className="text-[11px] text-muted-foreground">controles</p></div>
            </div>
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
                      <span className="w-24 shrink-0 font-mono text-xs text-neon">{c.id}</span>
                      <div className="min-w-0 flex-1">
                        <div className="mb-1 flex items-center justify-between gap-2">
                          <span className="truncate text-sm">{CONTROL_DESC[c.id] ?? 'Control del marco'}</span>
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
            Cada control refleja cuántos eventos del periodo aportan evidencia a ese requisito. No es una certificación:
            es la cobertura de monitoreo mapeada automáticamente por Wazuh a cada marco.
          </p>
        </>
      )}
    </div>
  );
}
