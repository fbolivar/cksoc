/**
 * UEBA — Comportamiento de usuarios. Muestra las anomalías de login que el motor
 * detecta al comparar la actividad reciente contra la línea base de cada usuario:
 * host nuevo, fuera de horario, pico de fallos, viaje imposible y país nuevo.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { AxiosError } from 'axios';
import {
  UserSearch, RefreshCw, Loader2, Play, Check, Ban, RotateCcw, Settings2,
  Plane, Globe, Clock, MonitorSmartphone, ShieldAlert,
} from 'lucide-react';
import {
  uebaApi, DETECTOR_ES, type Anomaly, type Detector, type Severity, type UebaSettings, type MonitoredEntity,
} from '@/lib/ueba';
import { useAuth } from '@/lib/auth';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';

const DETECTOR_ICON: Record<Detector, typeof Plane> = {
  impossible_travel: Plane,
  new_country: Globe,
  off_hours: Clock,
  new_host: MonitorSmartphone,
  auth_failure_spike: ShieldAlert,
};

const SEV: Record<Severity, { label: string; cls: string; dot: string }> = {
  critica: { label: 'Crítica', cls: 'text-rose-700 bg-rose-500/10 border-rose-500/30', dot: 'bg-rose-500' },
  alta: { label: 'Alta', cls: 'text-orange-700 bg-orange-500/10 border-orange-500/30', dot: 'bg-orange-500' },
  media: { label: 'Media', cls: 'text-amber-700 bg-amber-500/10 border-amber-500/30', dot: 'bg-amber-500' },
  baja: { label: 'Baja', cls: 'text-slate-600 bg-slate-500/10 border-slate-500/30', dot: 'bg-slate-400' },
};

const DETECTORS: Detector[] = ['impossible_travel', 'new_country', 'auth_failure_spike', 'new_host', 'off_hours'];

function timeAgo(iso: string): string {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 3600) return `hace ${Math.round(s / 60)} min`;
  if (s < 86400) return `hace ${Math.round(s / 3600)} h`;
  return `hace ${Math.round(s / 86400)} d`;
}

interface GeoEv { city?: string; country?: string; isoCode?: string }
interface EvidenceShape {
  from?: { geo?: GeoEv; srcip?: string }; to?: { geo?: GeoEv; srcip?: string };
  km?: number; kmh?: number; host?: string; usualHosts?: string[];
  count?: number; hosts?: string[]; geo?: GeoEv; srcip?: string; hour?: number;
}

function geoName(g?: GeoEv): string { return g?.city || g?.country || ''; }

function Evidence({ a }: { a: Anomaly }) {
  const e = a.evidence as EvidenceShape;
  if (a.detector === 'impossible_travel' && e.from && e.to) {
    return (
      <div className="mt-2 flex flex-wrap items-center gap-2 text-xs">
        <span className="rounded bg-secondary/60 px-2 py-1">{geoName(e.from.geo)} · {e.from.srcip}</span>
        <span className="text-muted-foreground">→ {e.km} km / {e.kmh} km/h →</span>
        <span className="rounded bg-secondary/60 px-2 py-1">{geoName(e.to.geo)} · {e.to.srcip}</span>
      </div>
    );
  }
  if (a.detector === 'new_host') {
    return (
      <div className="mt-2 text-xs text-muted-foreground">
        Host: <span className="font-medium text-foreground">{e.host}</span>
        {Array.isArray(e.usualHosts) && <> · Habituales: {e.usualHosts.slice(0, 6).join(', ')}</>}
      </div>
    );
  }
  if (a.detector === 'auth_failure_spike') {
    return <div className="mt-2 text-xs text-muted-foreground">{e.count} fallos · hosts: {(e.hosts ?? []).slice(0, 6).join(', ')}</div>;
  }
  if (a.detector === 'new_country' && e.geo) {
    return <div className="mt-2 text-xs text-muted-foreground">{e.geo.city ? e.geo.city + ', ' : ''}{e.geo.country} · {e.srcip}</div>;
  }
  if (a.detector === 'off_hours') {
    return <div className="mt-2 text-xs text-muted-foreground">{String(e.hour).padStart(2, '0')}:00 en {e.host}</div>;
  }
  return null;
}

export default function Ueba() {
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';
  const [data, setData] = useState<{ open: number; anomalies: Anomaly[] }>({ open: 0, anomalies: [] });
  const [status, setStatus] = useState('open');
  const [detector, setDetector] = useState<Detector | ''>('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const [showCfg, setShowCfg] = useState(false);
  const [cfg, setCfg] = useState<UebaSettings | null>(null);
  const [entities, setEntities] = useState<MonitoredEntity[]>([]);

  const seq = useRef(0);
  const load = useCallback(async () => {
    const my = ++seq.current;
    setLoading(true); setError(null);
    try {
      const res = await uebaApi.anomalies({ status, detector: detector || undefined, days: 30 });
      if (my === seq.current) setData(res);
      uebaApi.entities().then((r) => { if (my === seq.current) setEntities(r.entities); }).catch(() => undefined);
    } catch (e) {
      if (my === seq.current) setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudieron cargar las anomalías');
    } finally {
      if (my === seq.current) setLoading(false);
    }
  }, [status, detector]);
  useEffect(() => { void load(); }, [load]);

  const runScan = async () => {
    setScanning(true); setNote(null); setError(null);
    try {
      const r = await uebaApi.scan();
      setNote(`Escaneo: ${r.logins} logins de ${r.users} usuarios · ${r.anomalies} anomalías`);
      await load();
    } catch (e) {
      setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'Fallo al escanear');
    } finally { setScanning(false); }
  };

  const decide = async (id: string, decision: 'ack' | 'dismiss' | 'reopen') => {
    try { await uebaApi.decide(id, decision); await load(); }
    catch (e) { setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo actualizar'); }
  };

  const openCfg = async () => {
    setShowCfg((v) => !v);
    if (!cfg) { try { setCfg(await uebaApi.settings()); } catch { /* noop */ } }
  };
  const saveCfg = async () => {
    if (!cfg) return;
    try { setCfg(await uebaApi.updateSettings(cfg)); setNote('Configuración guardada'); }
    catch (e) { setError((e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo guardar'); }
  };

  const counts = DETECTORS.map((d) => ({ d, n: data.anomalies.filter((a) => a.detector === d).length }));

  return (
    <div className="mx-auto max-w-5xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="hw-mono flex items-center gap-2 text-2xl font-bold tracking-tight">
            <UserSearch className="h-6 w-6 text-primary" /> COMPORTAMIENTO · UEBA
          </h1>
          <p className="hw-mono text-[11px] tracking-wide text-muted-foreground">ANOMALÍAS DE LOGIN FRENTE A LA LÍNEA BASE DE CADA USUARIO</p>
        </div>
        <div className="flex items-center gap-2">
          {isAdmin && (
            <Button variant="outline" size="sm" onClick={openCfg}><Settings2 className="mr-1 h-4 w-4" /> Ajustes</Button>
          )}
          {isAdmin && (
            <Button variant="outline" size="sm" onClick={runScan} disabled={scanning}>
              {scanning ? <Loader2 className="mr-1 h-4 w-4 animate-spin" /> : <Play className="mr-1 h-4 w-4" />} Escanear
            </Button>
          )}
          <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
            <RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} />
          </Button>
        </div>
      </div>

      {note && <Card><CardContent className="p-3 text-sm text-emerald-700">{note}</CardContent></Card>}
      {error && <Card><CardContent className="p-3 text-sm text-amber-700">{error}</CardContent></Card>}

      {/* Ajustes */}
      {showCfg && cfg && (
        <Card>
          <CardContent className="grid gap-3 p-4 sm:grid-cols-3">
            <label className="text-xs">Inicio horario laboral
              <Input type="number" min={0} max={23} value={cfg.biz_start_hour} onChange={(ev) => setCfg({ ...cfg, biz_start_hour: Number(ev.target.value) })} /></label>
            <label className="text-xs">Fin horario laboral
              <Input type="number" min={1} max={24} value={cfg.biz_end_hour} onChange={(ev) => setCfg({ ...cfg, biz_end_hour: Number(ev.target.value) })} /></label>
            <label className="flex items-center gap-2 text-xs">Cuenta fin de semana
              <Switch checked={cfg.include_weekend} onChange={(v) => setCfg({ ...cfg, include_weekend: v })} /></label>
            <label className="text-xs">Línea base (días)
              <Input type="number" min={7} max={90} value={cfg.lookback_days} onChange={(ev) => setCfg({ ...cfg, lookback_days: Number(ev.target.value) })} /></label>
            <label className="text-xs">Ventana reciente (horas)
              <Input type="number" min={1} max={168} value={cfg.recent_hours} onChange={(ev) => setCfg({ ...cfg, recent_hours: Number(ev.target.value) })} /></label>
            <label className="text-xs">Umbral de fallos
              <Input type="number" min={3} max={100} value={cfg.fail_threshold} onChange={(ev) => setCfg({ ...cfg, fail_threshold: Number(ev.target.value) })} /></label>
            <label className="text-xs">Viaje imposible (km/h)
              <Input type="number" min={300} max={3000} value={cfg.impossible_kmh} onChange={(ev) => setCfg({ ...cfg, impossible_kmh: Number(ev.target.value) })} /></label>
            <div className="sm:col-span-3"><Button size="sm" onClick={saveCfg}><Check className="mr-1 h-4 w-4" /> Guardar</Button></div>
          </CardContent>
        </Card>
      )}

      {/* KPIs por detector */}
      <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-5">
        <Card className="border-l-2 border-l-primary/50"><CardContent className="p-3"><p className="hw-mono text-[10px] uppercase tracking-wider text-muted-foreground">Abiertas</p><p className="text-2xl font-bold tabular-nums">{data.open}</p></CardContent></Card>
        {counts.map(({ d, n }) => {
          const Icon = DETECTOR_ICON[d];
          return (
            <Card key={d} className="cursor-pointer hover:border-neon/40" onClick={() => setDetector(detector === d ? '' : d)}>
              <CardContent className="p-3">
                <p className="hw-mono flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-muted-foreground"><Icon className="h-3.5 w-3.5" /> {DETECTOR_ES[d]}</p>
                <p className={`text-2xl font-bold tabular-nums ${detector === d ? 'text-neon' : ''}`}>{n}</p>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Filtros de estado */}
      <div className="flex items-center gap-2">
        <div className="flex overflow-hidden rounded-md border border-input text-xs">
          {(['open', 'ack', 'dismissed', 'all'] as const).map((sVal) => (
            <button key={sVal} onClick={() => setStatus(sVal)}
              className={`px-3 py-1.5 ${status === sVal ? 'bg-secondary font-semibold text-foreground' : 'text-muted-foreground hover:bg-secondary/50'}`}>
              {sVal === 'open' ? 'Abiertas' : sVal === 'ack' ? 'Revisadas' : sVal === 'dismissed' ? 'Descartadas' : 'Todas'}
            </button>
          ))}
        </div>
        {detector && <button onClick={() => setDetector('')} className="text-xs text-neon underline">Quitar filtro: {DETECTOR_ES[detector]}</button>}
      </div>

      {/* Lista */}
      {loading && !data.anomalies.length ? (
        <p className="flex items-center gap-2 py-8 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Cargando…</p>
      ) : data.anomalies.length === 0 ? (
        <Card><CardContent className="p-8 text-center text-sm text-muted-foreground">Sin anomalías en este filtro. Un comportamiento dentro de lo normal es una buena noticia. 🟢</CardContent></Card>
      ) : (
        <div className="space-y-2.5">
          {data.anomalies.map((a) => {
            const sev = SEV[a.severity];
            const Icon = DETECTOR_ICON[a.detector];
            return (
              <Card key={a.id} className="overflow-hidden">
                <CardContent className="flex gap-3 p-4">
                  <div className={`mt-1 h-2 w-2 shrink-0 rounded-full ${sev.dot}`} />
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px] font-medium ${sev.cls}`}><Icon className="h-3 w-3" /> {DETECTOR_ES[a.detector]}</span>
                      <span className="text-[11px] text-muted-foreground">{sev.label} · score {a.score} · {a.source.toUpperCase()}</span>
                      <span className="ml-auto text-[11px] text-muted-foreground">{timeAgo(a.last_seen)}</span>
                    </div>
                    <p className="mt-1.5 text-sm font-medium">{a.title}</p>
                    <p className="text-xs text-muted-foreground">{a.summary}</p>
                    <Evidence a={a} />
                  </div>
                  <div className="flex shrink-0 flex-col gap-1.5">
                    {a.status !== 'ack' && <Button variant="outline" size="sm" onClick={() => decide(a.id, 'ack')} title="Marcar revisada"><Check className="h-4 w-4" /></Button>}
                    {a.status !== 'dismissed' && <Button variant="outline" size="sm" onClick={() => decide(a.id, 'dismiss')} title="Descartar"><Ban className="h-4 w-4" /></Button>}
                    {a.status !== 'open' && <Button variant="outline" size="sm" onClick={() => decide(a.id, 'reopen')} title="Reabrir"><RotateCcw className="h-4 w-4" /></Button>}
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
      {/* Entidades monitoreadas */}
      <Card>
        <CardContent className="p-4">
          <div className="mb-3 flex items-center justify-between">
            <p className="hw-mono text-[11px] uppercase tracking-wider text-muted-foreground">Entidades monitoreadas · últimos 7 días</p>
            <span className="text-[11px] text-muted-foreground">{entities.length} empleados</span>
          </div>
          {entities.length === 0 ? (
            <p className="py-4 text-center text-sm text-muted-foreground">Sin actividad de logins de empleados en la ventana.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-[11px] uppercase tracking-wider text-muted-foreground">
                    <th className="py-1.5 pr-3 font-medium">Usuario</th>
                    <th className="py-1.5 pr-3 font-medium">Logins</th>
                    <th className="py-1.5 pr-3 font-medium">Fallos</th>
                    <th className="py-1.5 pr-3 font-medium">Equipos</th>
                    <th className="py-1.5 pr-3 font-medium">Países</th>
                    <th className="py-1.5 font-medium">Último acceso</th>
                  </tr>
                </thead>
                <tbody>
                  {entities.map((e) => (
                    <tr key={e.user} className="border-b border-border/50 last:border-0">
                      <td className="py-1.5 pr-3 font-medium">{e.user}</td>
                      <td className="py-1.5 pr-3 tabular-nums">{e.logins}</td>
                      <td className={`py-1.5 pr-3 tabular-nums ${e.fails > 0 ? 'text-amber-600' : ''}`}>{e.fails}</td>
                      <td className="py-1.5 pr-3 text-muted-foreground">{e.hosts.join(', ') || '—'}</td>
                      <td className="py-1.5 pr-3 text-muted-foreground">{e.countries.join(', ') || '—'}</td>
                      <td className="py-1.5 text-muted-foreground">{timeAgo(e.lastSeen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
