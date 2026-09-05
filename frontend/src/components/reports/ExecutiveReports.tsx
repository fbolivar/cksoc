/**
 * Informe Gerencial de Seguridad (Dirección / Comité SGSI).
 *
 * Permite elegir el periodo (presets o rango de fechas), generar el informe,
 * revisar y editar cada una de sus secciones, previsualizarlo, descargar el
 * PDF y enviarlo al comité.
 */
import { useEffect, useState } from 'react';
import { AxiosError } from 'axios';
import {
  FileText, Download, Send, Save, Loader2, Calendar, CheckCircle2, AlertTriangle,
  RotateCcw, Trash2, Pencil, Sparkles, CalendarRange,
} from 'lucide-react';
import {
  executiveApi,
  type ExecPreview, type ExecReportRef, type PresetPeriodo, type ClaveSeccion, type TextosInforme,
} from '@/lib/reports';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';

/** Secciones editables, en el orden en el que aparecen en el documento. */
const SECCIONES: { key: ClaveSeccion; n: string; titulo: string; ayuda: string }[] = [
  { key: 'resumen', n: '—', titulo: 'Resumen ejecutivo', ayuda: 'Lo único que un directivo leerá con seguridad. Máximo tres párrafos.' },
  { key: 'introduccion', n: '1', titulo: 'Introducción', ayuda: 'Qué es este documento, para quién es y de dónde salen las cifras.' },
  { key: 'objetivos', n: '2', titulo: 'Objetivos', ayuda: 'Una línea por objetivo. Empieza cada línea con “- ”.' },
  { key: 'alcance', n: '3', titulo: 'Alcance y cobertura', ayuda: 'Qué se vigila, qué no y con qué limitaciones.' },
  { key: 'resultados', n: '4', titulo: 'Resultados del periodo', ayuda: 'Narrativa de los resultados. Las tablas y gráficas se generan automáticamente.' },
  { key: 'analisis', n: '5', titulo: 'Análisis', ayuda: 'Interpretación de las cifras. Usa **negrilla** para destacar.' },
  { key: 'conclusiones', n: '6', titulo: 'Conclusiones', ayuda: 'Una conclusión por línea, empezando con “- ”.' },
  { key: 'recomendaciones', n: '7', titulo: 'Recomendaciones', ayuda: 'Ordenadas por prioridad, una por línea.' },
  { key: 'planAccion', n: '8', titulo: 'Plan de acción', ayuda: 'Una acción por línea con el formato: acción | prioridad | responsable | fecha objetivo | indicador' },
  { key: 'hojaRuta', n: '9', titulo: 'Hoja de ruta', ayuda: 'Fases y sus iniciativas. Si lo dejas vacío se genera automáticamente por fases.' },
  { key: 'novedades', n: '10', titulo: 'Novedades del periodo', ayuda: 'Cambios operativos del mes (altas de equipos, ajustes). Una por línea con “- ”. Si lo dejas vacío se listan los equipos que empezaron a reportar.' },
];

const estadoBadge = (e: string) =>
  e === 'enviado' ? <Badge variant="success">enviado</Badge>
  : e === 'revisado' ? <Badge variant="default">revisado</Badge>
  : <Badge variant="muted">borrador</Badge>;

function hoyIso(): string {
  return new Date().toISOString().slice(0, 10);
}

function periodoTexto(r: ExecReportRef): string {
  if (r.periodoLabel) return r.periodoLabel;
  if (r.desde && r.hasta) return `${r.desde} a ${r.hasta}`;
  return r.mes;
}

export function ExecutiveReports({ onFlash }: { onFlash: (k: 'ok' | 'err', t: string) => void }) {
  const [presets, setPresets] = useState<PresetPeriodo[]>([]);
  const [preset, setPreset] = useState('mes-anterior');
  const [desde, setDesde] = useState(hoyIso().slice(0, 8) + '01');
  const [hasta, setHasta] = useState(hoyIso());

  const [current, setCurrent] = useState<ExecPreview | null>(null);
  const [textos, setTextos] = useState<TextosInforme | null>(null);
  const [seccion, setSeccion] = useState<ClaveSeccion>('resumen');
  const [sucio, setSucio] = useState<Set<ClaveSeccion>>(new Set());

  const [history, setHistory] = useState<ExecReportRef[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [confirmSend, setConfirmSend] = useState(false);

  const personalizado = preset === 'personalizado';

  const err = (e: unknown) =>
    onFlash('err', (e as AxiosError<{ error?: string }>).response?.data?.error ?? 'Ocurrió un error');

  async function loadHistory() {
    setHistory(await executiveApi.history().catch(() => []));
  }
  useEffect(() => {
    executiveApi.presets().then(setPresets).catch(() => setPresets([]));
    loadHistory();
  }, []);

  function aplicar(p: ExecPreview) {
    setCurrent(p);
    setTextos(p.textos);
    setSucio(new Set());
  }

  async function generate() {
    setBusy('gen');
    try {
      const p = personalizado
        ? await executiveApi.generate({ preset, desde, hasta })
        : await executiveApi.generate({ preset });
      aplicar(p);
      await loadHistory();
      onFlash('ok', `Informe de ${periodoTexto(p.report)} generado (borrador)`);
    } catch (e) { err(e); } finally { setBusy(null); }
  }

  async function open(id: string) {
    setBusy('open');
    try { aplicar(await executiveApi.get(id)); } catch (e) { err(e); } finally { setBusy(null); }
  }

  async function guardar() {
    if (!current || !textos || sucio.size === 0) return;
    setBusy('save');
    try {
      const cambios: Partial<TextosInforme> = {};
      for (const k of sucio) cambios[k] = textos[k];
      aplicar(await executiveApi.update(current.report.id, cambios));
      await loadHistory();
      onFlash('ok', 'Cambios guardados y documento regenerado');
    } catch (e) { err(e); } finally { setBusy(null); }
  }

  /** Devuelve una sección al texto generado automáticamente. */
  async function restablecer(k: ClaveSeccion) {
    if (!current) return;
    setBusy('save');
    try {
      aplicar(await executiveApi.update(current.report.id, { [k]: '' } as Partial<TextosInforme>));
      onFlash('ok', 'Sección restablecida al texto generado automáticamente');
    } catch (e) { err(e); } finally { setBusy(null); }
  }

  async function download() {
    if (!current) return;
    setBusy('dl');
    try { await executiveApi.download(current.report); }
    catch { onFlash('err', 'No se pudo descargar el PDF'); } finally { setBusy(null); }
  }

  async function send() {
    if (!current) return;
    setBusy('send');
    try {
      const r = await executiveApi.send(current.report.id);
      setConfirmSend(false);
      onFlash('ok', `Informe enviado (${r.recipients.length} destinatario(s))`);
      await open(current.report.id);
      await loadHistory();
    } catch (e) { err(e); setConfirmSend(false); } finally { setBusy(null); }
  }

  async function eliminar(r: ExecReportRef) {
    if (!confirm(`¿Eliminar el informe de ${periodoTexto(r)}?`)) return;
    try {
      await executiveApi.remove(r.id);
      if (current?.report.id === r.id) { setCurrent(null); setTextos(null); }
      await loadHistory();
      onFlash('ok', 'Informe eliminado');
    } catch (e) { err(e); }
  }

  const editada = (k: ClaveSeccion) => current?.editadas.includes(k) || sucio.has(k);
  const meta = SECCIONES.find((s) => s.key === seccion)!;

  return (
    <div className="space-y-4">
      {/* ---------- Generador ---------- */}
      <Card>
        <CardHeader>
          <CardTitle className="text-muted-foreground">Informe gerencial de seguridad · Dirección y Comité</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex flex-wrap items-end gap-3">
            <div className="space-y-2">
              <Label>Periodo</Label>
              <select
                value={preset}
                onChange={(e) => setPreset(e.target.value)}
                className="h-10 w-56 rounded-md border border-input bg-background/60 px-3 text-sm"
              >
                {presets.length === 0 && <option value="mes-anterior">Mes anterior</option>}
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

            <Button onClick={generate} disabled={busy === 'gen'}>
              {busy === 'gen' ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileText className="h-4 w-4" />}
              {busy === 'gen' ? 'Analizando periodo…' : 'Generar informe'}
            </Button>
          </div>

          <div className="flex items-start gap-2 rounded-md border border-border/50 bg-card/40 px-3 py-2 text-[11px] text-muted-foreground">
            <Sparkles className="mt-0.5 h-3.5 w-3.5 shrink-0 text-primary" />
            <span>
              Documento de 10 secciones en lenguaje no técnico: introducción, objetivos, alcance, resultados,
              análisis comparativo con el periodo anterior, conclusiones, recomendaciones priorizadas,
              plan de acción con responsables y fechas, hoja de ruta por fases y anexos con glosario.
              Todas las secciones son editables antes de publicar.
            </span>
          </div>
        </CardContent>
      </Card>

      {/* ---------- Editor + vista previa ---------- */}
      {current && textos && (
        <Card>
          <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2 space-y-0">
            <CardTitle className="flex items-center gap-2">
              <CalendarRange className="h-4 w-4" /> {periodoTexto(current.report)} {estadoBadge(current.report.estado)}
              {sucio.size > 0 && <span className="text-[11px] font-normal text-amber-400">· {sucio.size} sección(es) sin guardar</span>}
            </CardTitle>
            <div className="flex flex-wrap gap-2">
              <Button variant="outline" size="sm" onClick={guardar} disabled={!!busy || sucio.size === 0}>
                {busy === 'save' ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />} Guardar
              </Button>
              <Button variant="outline" size="sm" onClick={download} disabled={!!busy}>
                {busy === 'dl' ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />} Descargar PDF
              </Button>
              <Button size="sm" onClick={() => setConfirmSend(true)} disabled={!!busy}>
                <Send className="h-4 w-4" /> Enviar al comité
              </Button>
            </div>
          </CardHeader>

          <CardContent className="space-y-4">
            <div className="grid gap-4 lg:grid-cols-[210px_1fr]">
              {/* Índice de secciones */}
              <div className="space-y-1">
                <Label className="mb-1 block text-[11px] uppercase tracking-wide text-muted-foreground">Secciones</Label>
                {SECCIONES.map((s) => (
                  <button
                    key={s.key}
                    onClick={() => setSeccion(s.key)}
                    className={`flex w-full items-center gap-2 rounded-md px-2.5 py-1.5 text-left text-[12px] transition-colors ${
                      seccion === s.key ? 'bg-primary/12 font-medium text-foreground' : 'text-muted-foreground hover:bg-foreground/5'
                    }`}
                  >
                    <span className="hw-mono w-4 shrink-0 text-[10px] text-muted-foreground">{s.n}</span>
                    <span className="flex-1 truncate">{s.titulo}</span>
                    {editada(s.key) && <Pencil className="h-3 w-3 shrink-0 text-amber-400" />}
                  </button>
                ))}
              </div>

              {/* Editor de la sección activa */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label>{meta.titulo}</Label>
                  {editada(seccion) && (
                    <Button variant="ghost" size="sm" onClick={() => restablecer(seccion)} disabled={!!busy}>
                      <RotateCcw className="h-3.5 w-3.5" /> Restablecer automático
                    </Button>
                  )}
                </div>
                <p className="text-[11px] text-muted-foreground">{meta.ayuda}</p>
                <Textarea
                  value={textos[seccion]}
                  onChange={(e) => {
                    setTextos({ ...textos, [seccion]: e.target.value });
                    setSucio(new Set(sucio).add(seccion));
                  }}
                  className="min-h-[260px] font-mono text-[12px] leading-relaxed"
                />
              </div>
            </div>

            {/* Vista previa */}
            <div>
              <Label className="mb-2 block">Vista previa del documento</Label>
              <iframe
                title="preview"
                srcDoc={current.html}
                // sandbox="" (sin allow-scripts/allow-same-origin): el informe es solo
                // presentacion; bloquear JS evita XSS si algun dato del SOC arrastra markup.
                sandbox=""
                className="h-[700px] w-full rounded-lg border border-border/60 bg-white"
              />
              <p className="mt-1 text-[11px] text-muted-foreground">
                La vista previa refleja la última versión guardada. Pulsa <b>Guardar</b> para ver tus cambios aquí y en el PDF.
              </p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* ---------- Historial ---------- */}
      <Card>
        <CardHeader>
          <CardTitle className="text-muted-foreground">Informes generados ({history.length})</CardTitle>
        </CardHeader>
        <CardContent>
          {history.length === 0 ? (
            <p className="py-4 text-center text-sm text-muted-foreground">Aún no se han generado informes gerenciales.</p>
          ) : (
            <div className="space-y-2">
              {history.map((r) => (
                <div key={r.id} className="flex flex-wrap items-center gap-3 rounded-md border border-border/50 bg-card/40 px-3 py-2.5">
                  <Calendar className="h-4 w-4 text-muted-foreground" />
                  <span className="font-medium capitalize">{periodoTexto(r)}</span>
                  {estadoBadge(r.estado)}
                  <span className="text-xs text-muted-foreground">
                    {r.generado_en ? new Date(r.generado_en).toLocaleString('es-CO') : ''}
                    {r.enviado_en ? ` · enviado ${new Date(r.enviado_en).toLocaleDateString('es-CO')}` : ''}
                  </span>
                  <div className="ml-auto flex items-center gap-1">
                    <Button variant="ghost" size="sm" onClick={() => open(r.id)}>Abrir</Button>
                    <Button variant="ghost" size="icon" title="Descargar PDF" onClick={() => executiveApi.download(r)}>
                      <Download className="h-4 w-4" />
                    </Button>
                    <Button variant="ghost" size="icon" title="Eliminar" onClick={() => eliminar(r)}>
                      <Trash2 className="h-4 w-4 text-red-400" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* ---------- Confirmación de envío ---------- */}
      {confirmSend && current && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={() => setConfirmSend(false)}>
          <div className="w-full max-w-md rounded-lg border border-border/70 bg-card shadow-2xl" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center gap-3 border-b border-border/60 px-5 py-4">
              <Send className="h-5 w-5 text-neon" />
              <h3 className="font-semibold">Enviar al Comité de Seguridad</h3>
            </div>
            <div className="space-y-3 p-5">
              <div className="flex items-start gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-sm">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
                <span className="text-amber-100">
                  Se enviará el informe de <b>{periodoTexto(current.report)}</b> con el PDF adjunto a los destinatarios
                  configurados. {sucio.size > 0 && <b>Tienes cambios sin guardar que no se incluirán.</b>} ¿Confirmas el envío?
                </span>
              </div>
              <div className="flex justify-end gap-2">
                <Button variant="outline" onClick={() => setConfirmSend(false)} disabled={busy === 'send'}>Cancelar</Button>
                <Button onClick={send} disabled={busy === 'send'}>
                  {busy === 'send' ? <Loader2 className="h-4 w-4 animate-spin" /> : <CheckCircle2 className="h-4 w-4" />} Confirmar envío
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
