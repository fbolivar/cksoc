import { useEffect, useState } from 'react';
import { Cloud, RefreshCw, AlertTriangle, Trash2, FileEdit, Download, Share2, Link2 } from 'lucide-react';
import { cloudDataApi, type CdOverview, type Sev } from '@/lib/clouddata';

const RANGES = [{ d: '24h', l: '24 h' }, { d: '7d', l: '7 días' }, { d: '30d', l: '30 días' }];
const SEV: Record<Sev, string> = {
  critica: 'bg-red-500/15 text-red-500 border-red-500/40',
  alta: 'bg-orange-500/15 text-orange-400 border-orange-500/40',
  media: 'bg-amber-500/15 text-amber-500 border-amber-500/40',
};
function icon(t: string) {
  if (t === 'borrado_masivo') return <Trash2 className="h-4 w-4 text-red-400" />;
  if (t === 'modificacion_masiva') return <FileEdit className="h-4 w-4 text-orange-400" />;
  if (t === 'descarga_masiva') return <Download className="h-4 w-4 text-amber-400" />;
  if (t === 'enlaces_anonimos') return <Link2 className="h-4 w-4 text-amber-400" />;
  return <Share2 className="h-4 w-4 text-slate-400" />;
}

function Kpi({ label, value }: { label: string; value: number }) {
  return (
    <div className="glass rounded-lg p-3">
      <div className={`text-2xl font-bold ${value > 0 ? 'text-red-500' : 'text-foreground'}`}>{value}</div>
      <div className="text-[11px] text-muted-foreground">{label}</div>
    </div>
  );
}

export default function CloudData() {
  const [days, setDays] = useState('24h');
  const [d, setD] = useState<CdOverview | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function load(dd: string) {
    setLoading(true); setErr(null);
    try { setD(await cloudDataApi.get(dd)); }
    catch { setErr('No se pudo consultar el riesgo de datos en nube (indexer O365).'); }
    finally { setLoading(false); }
  }
  useEffect(() => { void load(days); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [days]);

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-bold"><Cloud className="h-5 w-5 text-brand" /> Riesgo de Datos en Nube (M365)</h1>
          <p className="text-sm text-muted-foreground">Ráfagas por usuario en OneDrive/SharePoint: borrado masivo (ransomware/sabotaje), modificación/cifrado, descarga (exfiltración) y compartición externa.</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex rounded-lg border border-border bg-secondary/40 p-0.5">
            {RANGES.map((r) => <button key={r.d} onClick={() => setDays(r.d)} className={`rounded-md px-3 py-1 text-xs transition ${days === r.d ? 'bg-brand text-white' : 'text-muted-foreground hover:text-foreground'}`}>{r.l}</button>)}
          </div>
          <button onClick={() => void load(days)} disabled={loading} className="inline-flex items-center gap-1 rounded-lg border border-border bg-secondary/40 px-3 py-1.5 text-xs hover:bg-secondary disabled:opacity-50">
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} /> Actualizar
          </button>
        </div>
      </div>

      {err && <div className="flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-2 text-xs text-amber-600"><AlertTriangle className="h-4 w-4" /> {err}</div>}

      {d && (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
            <Kpi label="Borrado masivo" value={d.kpis.borrado} />
            <Kpi label="Modificación" value={d.kpis.modificacion} />
            <Kpi label="Descarga" value={d.kpis.descarga} />
            <Kpi label="Compartición ext." value={d.kpis.comparticion} />
            <Kpi label="Enlaces anónimos" value={d.kpis.anonimo} />
          </div>

          <div className="glass rounded-lg p-4">
            <p className="mb-3 text-sm font-semibold">Ráfagas detectadas ({d.hallazgos.length})</p>
            {d.hallazgos.length === 0 ? (
              <p className="py-6 text-center text-xs text-muted-foreground">Sin ráfagas sobre umbral en el rango. 👍</p>
            ) : (
              <div className="max-h-[520px] space-y-1.5 overflow-y-auto">
                {d.hallazgos.map((h, i) => (
                  <div key={i} className="rounded border-l-2 border-l-border bg-secondary/20 px-2.5 py-1.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="flex min-w-0 items-center gap-1.5 text-xs font-medium">{icon(h.tipo)} <span className="truncate">{h.tipoLabel}</span></span>
                      <span className={`shrink-0 rounded border px-1.5 py-0.5 text-[9px] font-semibold uppercase ${SEV[h.sev]}`}>{h.sev}</span>
                    </div>
                    <p className="mt-0.5 truncate text-[11px] text-muted-foreground"><b className="text-foreground">{h.user}</b> — {h.count.toLocaleString('es-CO')} operaciones <span className="text-muted-foreground/60">(umbral {h.umbral})</span></p>
                  </div>
                ))}
              </div>
            )}
          </div>
          <p className="text-center text-[11px] text-muted-foreground/60">Umbrales por usuario: borrado {d.umbrales.del} · modif. {d.umbrales.mod} · descarga {d.umbrales.dl} · compartición {d.umbrales.share} · anónimo {d.umbrales.anon}. Fuente: auditoría O365 vía Wazuh. Actualizado {new Date(d.generatedAt).toLocaleTimeString('es-CO')}.</p>
        </>
      )}
      {loading && !d && <div className="glass h-40 animate-pulse rounded-lg" />}
    </div>
  );
}
