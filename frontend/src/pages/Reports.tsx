/**
 * Página de Reportes.
 *  - Técnico: informe operativo del SOC (hallazgos con evidencia, consultas,
 *    plan de acción y hoja de ruta por sprints) para un periodo arbitrario.
 *  - Gerencial: informe de dirección, editable por secciones.
 */
import { useEffect, useState } from 'react';
import { AxiosError } from 'axios';
import {
  FileBarChart,
  Download,
  Trash2,
  Loader2,
  CalendarClock,
  FileText,
  LineChart,
  AlertTriangle,
  ClipboardCheck,
  Timer,
  ShieldCheck,
  ScrollText,
  Eye,
  Sparkles,
  X,
  Send,
  Sunrise,
  Sunset,
} from 'lucide-react';
import { useAuth } from '@/lib/auth';
import { reportsApi, shiftApi, type Report, type PresetPeriodo, type Turno, type ShiftStatus } from '@/lib/reports';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { ExecutiveReports } from '@/components/reports/ExecutiveReports';

function hoyIso(): string {
  return new Date().toISOString().slice(0, 10);
}

/** Texto del periodo de un reporte del historial. */
function periodoDe(r: Report): string {
  if (r.params?.label) return r.params.label;
  if (r.params?.desde && r.params?.hasta) return `${r.params.desde} a ${r.params.hasta}`;
  return r.params?.range ?? '—';
}

export default function Reports() {
  const { user } = useAuth();
  const canManage = user?.role === 'admin' || user?.role === 'analista';
  const isAdmin = user?.role === 'admin';
  const [tab, setTab] = useState<'tecnico' | 'ejecutivo'>('tecnico');

  const [reports, setReports] = useState<Report[]>([]);
  const [presets, setPresets] = useState<PresetPeriodo[]>([]);
  const [title, setTitle] = useState('Informe técnico del SOC');
  const [preset, setPreset] = useState('ultimas-24h');
  const [desde, setDesde] = useState(hoyIso().slice(0, 8) + '01');
  const [hasta, setHasta] = useState(hoyIso());
  const [generating, setGenerating] = useState(false);
  const [downloading, setDownloading] = useState<string | null>(null);
  const [preview, setPreview] = useState<{ html: string; title: string } | null>(null);
  const [loadingPreview, setLoadingPreview] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  // Parte de Estado (shift report AM/PM)
  const [shiftStatus, setShiftStatus] = useState<ShiftStatus | null>(null);
  const [shiftTurno, setShiftTurno] = useState<Turno>(new Date().getHours() < 12 ? 'am' : 'pm');
  const [shiftBusy, setShiftBusy] = useState<'send' | 'preview' | null>(null);

  const personalizado = preset === 'personalizado';

  async function reload() {
    setReports(await reportsApi.list());
  }
  useEffect(() => {
    reload().catch(() => setMsg({ kind: 'err', text: 'No se pudo cargar el historial' }));
    reportsApi.presets().then(setPresets).catch(() => setPresets([]));
  }, []);

  const flash = (kind: 'ok' | 'err', text: string) => {
    setMsg({ kind, text });
    setTimeout(() => setMsg(null), 5000);
  };
  const err = (e: unknown, fallback: string) =>
    flash('err', (e as AxiosError<{ error?: string }>).response?.data?.error ?? fallback);

  async function generate() {
    setGenerating(true);
    setMsg(null);
    try {
      const r = await reportsApi.generate(
        personalizado ? { title, preset, desde, hasta } : { title, preset }
      );
      await reload();
      flash('ok', `Informe de ${periodoDe(r)} generado`);
      await openPreview(r.id);
    } catch (e) {
      err(e, 'No se pudo generar el informe');
    } finally {
      setGenerating(false);
    }
  }

  async function openPreview(id: string) {
    setLoadingPreview(id);
    try {
      setPreview(await reportsApi.preview(id));
    } catch (e) {
      err(e, 'No se pudo abrir la vista previa');
    } finally {
      setLoadingPreview(null);
    }
  }

  async function download(r: Report) {
    setDownloading(r.id);
    try {
      await reportsApi.download(r.id, r.title);
    } catch {
      flash('err', 'No se pudo descargar el reporte');
    } finally {
      setDownloading(null);
    }
  }

  async function remove(r: Report) {
    if (!confirm(`¿Eliminar el reporte "${r.title}"?`)) return;
    try {
      await reportsApi.remove(r.id);
      await reload();
      flash('ok', 'Reporte eliminado');
    } catch {
      flash('err', 'No se pudo eliminar');
    }
  }

  useEffect(() => {
    if (canManage) shiftApi.status().then(setShiftStatus).catch(() => undefined);
  }, [canManage]);

  async function shiftPreview() {
    setShiftBusy('preview');
    try {
      const html = await shiftApi.preview(shiftTurno);
      const w = window.open('', '_blank');
      if (w) { w.document.open(); w.document.write(html); w.document.close(); }
    } catch {
      flash('err', 'No se pudo generar la vista previa del parte');
    } finally {
      setShiftBusy(null);
    }
  }

  async function shiftSend() {
    const label = shiftTurno === 'am' ? 'Mañana' : 'Tarde';
    const dest = shiftStatus?.internal ? 'al chat INTERNO de revisión' : 'al cliente';
    if (!confirm(`¿Generar y enviar el Parte de Estado (${label}) ${dest}?`)) return;
    setShiftBusy('send');
    try {
      const r = await shiftApi.send(shiftTurno);
      flash('ok', r.internal
        ? `Parte enviado al chat interno de revisión (${r.filename}). Cuando lo apruebes, configuramos el envío al cliente.`
        : `Parte enviado al cliente · ${r.sentTo.length} destinatario(s) (${r.filename}).`);
    } catch (e) {
      const err = e as AxiosError<{ error?: string }>;
      flash('err', err.response?.data?.error ?? 'No se pudo enviar el parte');
    } finally {
      setShiftBusy(null);
    }
  }

  /** Preselecciona título y periodo desde el catálogo. */
  const pick = (t: string, p: string, exec?: boolean) => {
    if (exec && isAdmin) { setTab('ejecutivo'); return; }
    setTab('tecnico'); setTitle(t); setPreset(p);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };
  const catalog: { icon: typeof FileText; col: string; title: string; desc: string; fmt: string; cadence: string; onClick: () => void }[] = [
    { icon: LineChart, col: 'primary', title: 'Informe gerencial', desc: 'Documento para dirección: análisis, plan de acción y hoja de ruta.', fmt: 'PDF', cadence: 'Por periodo', onClick: () => pick('Informe gerencial', 'mes-anterior', true) },
    { icon: ShieldCheck, col: 'cyan', title: 'Informe técnico del turno', desc: 'Hallazgos con evidencia y consultas reproducibles de las últimas 24 h.', fmt: 'PDF', cadence: 'Diario', onClick: () => pick('Informe técnico del SOC · turno', 'ultimas-24h') },
    { icon: AlertTriangle, col: 'destructive', title: 'Revisión semanal', desc: 'Panorama de detecciones, vulnerabilidades priorizadas y tuning de reglas.', fmt: 'PDF', cadence: 'Semanal', onClick: () => pick('Revisión técnica semanal del SOC', 'ultimos-7d') },
    { icon: ClipboardCheck, col: 'warn-orange', title: 'Cierre de mes técnico', desc: 'Cobertura ATT&CK, higiene de detección y deuda de seguridad del mes.', fmt: 'PDF', cadence: 'Mensual', onClick: () => pick('Cierre técnico mensual del SOC', 'mes-anterior') },
    { icon: Timer, col: 'primary', title: 'Ventana de incidente', desc: 'Informe acotado a un rango exacto para soportar una investigación.', fmt: 'PDF', cadence: 'Bajo demanda', onClick: () => pick('Informe técnico · ventana de incidente', 'personalizado') },
    { icon: ScrollText, col: 'success', title: 'Últimos 30 días', desc: 'Tendencia, picos de volumen y evolución de la postura técnica.', fmt: 'PDF', cadence: 'Bajo demanda', onClick: () => pick('Informe técnico · últimos 30 días', 'ultimos-30d') },
  ];

  return (
    <div className="mx-auto max-w-5xl space-y-5">
      <div>
        <h1 className="hw-mono flex items-center gap-2 text-2xl font-bold tracking-tight">
          <FileBarChart className="h-6 w-6 text-primary" /> REPORTES
        </h1>
        <p className="hw-mono text-[11px] tracking-wide text-muted-foreground">GENERA // ANALIZA // DESCARGA</p>
      </div>

      {/* Catálogo */}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {catalog.map((c) => (
          <button key={c.title} onClick={c.onClick} className="hud text-left transition-transform hover:-translate-y-0.5">
            <span className="hw-clip mb-3 flex h-9 w-9 items-center justify-center" style={{ background: `hsl(var(--${c.col}) / .14)`, color: `hsl(var(--${c.col}))` }}><c.icon className="h-[18px] w-[18px]" /></span>
            <h3 className="text-[14px] font-bold">{c.title}</h3>
            <p className="mt-1 text-[12px] leading-relaxed text-muted-foreground">{c.desc}</p>
            <div className="hw-mono mt-3 flex items-center gap-2 text-[10px] text-foreground/70"><span className="bg-foreground/8 px-1.5 py-0.5">{c.fmt}</span>{c.cadence}</div>
          </button>
        ))}
      </div>

      {/* Parte de Estado (dos veces al día, para el cliente) */}
      {canManage && (
        <div className="hud">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="min-w-[240px] flex-1">
              <h3 className="flex items-center gap-2 text-[14px] font-bold">
                <Send className="h-[18px] w-[18px] text-primary" /> Parte de Estado del Servicio
              </h3>
              <p className="mt-1 text-[12px] leading-relaxed text-muted-foreground">
                Resumen de una página con el estado real de las estaciones para enviar al cliente
                por Telegram (mañana y tarde). Muestra cobertura, eventos procesados, incidentes y
                las estaciones en atención.
              </p>
              <div className="hw-mono mt-2 flex flex-wrap items-center gap-2 text-[10px]">
                {shiftStatus == null ? (
                  <span className="text-muted-foreground">cargando estado…</span>
                ) : !shiftStatus.telegramReady ? (
                  <span className="px-1.5 py-0.5" style={{ background: 'hsl(var(--destructive) / .12)', color: 'hsl(var(--destructive))' }}>Telegram no configurado</span>
                ) : shiftStatus.internal ? (
                  <span className="px-1.5 py-0.5" style={{ background: 'hsl(var(--warn-orange) / .14)', color: 'hsl(var(--warn-orange))' }}>
                    ENVÍO INTERNO DE REVISIÓN · aún no va al cliente
                  </span>
                ) : (
                  <span className="px-1.5 py-0.5" style={{ background: 'hsl(var(--success) / .14)', color: 'hsl(var(--success))' }}>
                    ENVÍO AL CLIENTE · {shiftStatus.destinatarios} destinatario(s)
                  </span>
                )}
                <span className="bg-foreground/8 px-1.5 py-0.5">Programación 09:00 / 15:00 (apagada)</span>
              </div>
            </div>

            <div className="flex flex-col items-stretch gap-2">
              {/* Selector de turno */}
              <div className="inline-flex rounded-md border border-border/60 p-0.5">
                <button
                  onClick={() => setShiftTurno('am')}
                  className={`flex items-center gap-1.5 rounded px-2.5 py-1 text-[12px] font-medium transition-colors ${shiftTurno === 'am' ? 'bg-foreground/10 text-foreground' : 'text-muted-foreground hover:text-foreground'}`}>
                  <Sunrise className="h-3.5 w-3.5" /> Mañana
                </button>
                <button
                  onClick={() => setShiftTurno('pm')}
                  className={`flex items-center gap-1.5 rounded px-2.5 py-1 text-[12px] font-medium transition-colors ${shiftTurno === 'pm' ? 'bg-foreground/10 text-foreground' : 'text-muted-foreground hover:text-foreground'}`}>
                  <Sunset className="h-3.5 w-3.5" /> Tarde
                </button>
              </div>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={shiftPreview} disabled={shiftBusy != null}>
                  {shiftBusy === 'preview' ? <Loader2 className="mr-1.5 h-4 w-4 animate-spin" /> : <Eye className="mr-1.5 h-4 w-4" />}
                  Vista previa
                </Button>
                <Button size="sm" onClick={shiftSend} disabled={shiftBusy != null || shiftStatus?.telegramReady === false}>
                  {shiftBusy === 'send' ? <Loader2 className="mr-1.5 h-4 w-4 animate-spin" /> : <Send className="mr-1.5 h-4 w-4" />}
                  Enviar parte ahora
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}

      {msg && (
        <div
          className={`rounded-md border px-3 py-2 text-sm ${
            msg.kind === 'ok'
              ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200'
              : 'border-destructive/40 bg-destructive/10 text-destructive'
          }`}
        >
          {msg.text}
        </div>
      )}

      {/* Pestañas */}
      <div className="flex gap-1 border-b border-border/60">
        <button onClick={() => setTab('tecnico')}
          className={`px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors ${tab === 'tecnico' ? 'border-primary text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground'}`}>
          Técnico (SOC)
        </button>
        {isAdmin && (
          <button onClick={() => setTab('ejecutivo')}
            className={`px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors ${tab === 'ejecutivo' ? 'border-primary text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground'}`}>
            Gerencial (Dirección)
          </button>
        )}
      </div>

      {tab === 'ejecutivo' && isAdmin && <ExecutiveReports onFlash={flash} />}

      {tab === 'tecnico' && (<>
      {/* Generador */}
      {canManage && (
        <Card>
          <CardHeader>
            <CardTitle className="text-muted-foreground">Generar informe técnico</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex flex-wrap items-end gap-3">
              <div className="flex-1 space-y-2" style={{ minWidth: 240 }}>
                <Label htmlFor="rtitle">Título</Label>
                <Input id="rtitle" value={title} onChange={(e) => setTitle(e.target.value)} />
              </div>
              <div className="space-y-2">
                <Label>Periodo</Label>
                <select
                  value={preset}
                  onChange={(e) => setPreset(e.target.value)}
                  className="h-10 w-52 rounded-md border border-input bg-background/60 px-3 text-sm"
                >
                  {presets.length === 0 && <option value="ultimas-24h">Últimas 24 horas</option>}
                  {presets.map((p) => (
                    <option key={p.value} value={p.value}>{p.label}</option>
                  ))}
                </select>
              </div>
              {personalizado && (
                <>
                  <div className="space-y-2">
                    <Label>Desde</Label>
                    <Input type="date" value={desde} max={hasta} onChange={(e) => setDesde(e.target.value)} className="w-40" />
                  </div>
                  <div className="space-y-2">
                    <Label>Hasta</Label>
                    <Input type="date" value={hasta} min={desde} max={hoyIso()} onChange={(e) => setHasta(e.target.value)} className="w-40" />
                  </div>
                </>
              )}
              <Button onClick={generate} disabled={generating || !title}>
                {generating ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileText className="h-4 w-4" />}
                {generating ? 'Analizando…' : 'Generar informe'}
              </Button>
            </div>
            <div className="flex items-start gap-2 rounded-md border border-border/50 bg-card/40 px-3 py-2 text-[11px] text-muted-foreground">
              <Sparkles className="mt-0.5 h-3.5 w-3.5 shrink-0 text-primary" />
              <span>
                Documento operativo: alcance y salud de la telemetría, panorama de detecciones con picos,
                análisis por dominio (accesos, perímetro, ATT&CK, integridad, vulnerabilidades, hardening,
                inteligencia), hallazgos priorizados con evidencia y la consulta para reproducirlos,
                plan de acción con responsable y criterio de cierre, y hoja de ruta por sprints.
              </span>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Reporte programado */}
      <Card>
        <CardContent className="flex items-center gap-3 p-4">
          <CalendarClock className="h-5 w-5 text-neon" />
          <div className="text-sm">
            <p className="font-medium">Informe programado</p>
            <p className="text-muted-foreground">
              Se genera automáticamente según la programación configurada. Si hay SMTP definido,
              se envía por correo a los destinatarios del equipo técnico.
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Historial */}
      <Card>
        <CardHeader>
          <CardTitle className="text-muted-foreground">Historial de informes ({reports.length})</CardTitle>
        </CardHeader>
        <CardContent>
          {reports.length === 0 ? (
            <p className="py-6 text-center text-sm text-muted-foreground">
              No hay informes todavía.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border/60 text-left text-xs text-muted-foreground">
                    <th className="pb-2 pr-4 font-medium">Fecha</th>
                    <th className="pb-2 pr-4 font-medium">Título</th>
                    <th className="pb-2 pr-4 font-medium">Tipo</th>
                    <th className="pb-2 pr-4 font-medium">Periodo</th>
                    <th className="pb-2 font-medium text-right">Acciones</th>
                  </tr>
                </thead>
                <tbody>
                  {reports.map((r) => (
                    <tr key={r.id} className="border-b border-border/30 last:border-0">
                      <td className="py-2.5 pr-4 text-muted-foreground">
                        {new Date(r.created_at).toLocaleString('es-CO')}
                      </td>
                      <td className="py-2.5 pr-4 font-medium">{r.title}</td>
                      <td className="py-2.5 pr-4">
                        {r.type === 'scheduled' ? (
                          <Badge variant="default">programado</Badge>
                        ) : (
                          <Badge variant="muted">manual</Badge>
                        )}
                      </td>
                      <td className="py-2.5 pr-4 text-muted-foreground">{periodoDe(r)}</td>
                      <td className="py-2.5">
                        <div className="flex justify-end gap-1">
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => openPreview(r.id)}
                            disabled={loadingPreview === r.id}
                            title="Ver informe"
                          >
                            {loadingPreview === r.id ? <Loader2 className="h-4 w-4 animate-spin" /> : <Eye className="h-4 w-4" />}
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => download(r)}
                            disabled={downloading === r.id}
                            title="Descargar PDF"
                          >
                            {downloading === r.id ? (
                              <Loader2 className="h-4 w-4 animate-spin" />
                            ) : (
                              <Download className="h-4 w-4" />
                            )}
                          </Button>
                          {canManage && (
                            <Button variant="ghost" size="icon" onClick={() => remove(r)} title="Eliminar">
                              <Trash2 className="h-4 w-4 text-red-400" />
                            </Button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
      </>)}

      {/* Vista previa a pantalla completa */}
      {preview && (
        <div className="fixed inset-0 z-50 flex flex-col bg-black/70 p-4" onClick={() => setPreview(null)}>
          <div
            className="mx-auto flex h-full w-full max-w-4xl flex-col overflow-hidden rounded-lg border border-border/70 bg-card shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b border-border/60 px-4 py-3">
              <h3 className="truncate text-sm font-semibold">{preview.title}</h3>
              <Button variant="ghost" size="icon" onClick={() => setPreview(null)} title="Cerrar">
                <X className="h-4 w-4" />
              </Button>
            </div>
            <iframe
              title="preview-tecnico"
              srcDoc={preview.html}
              // sandbox="" (sin allow-scripts/allow-same-origin): el informe es solo
              // presentacion; bloquear JS evita XSS si algun dato del SOC arrastra markup.
              sandbox=""
              className="h-full w-full flex-1 bg-white"
            />
          </div>
        </div>
      )}
    </div>
  );
}
