/**
 * Reporte Ejecutivo Mensual (Comite SGSI): generar, previsualizar, editar el
 * texto ejecutivo, descargar PDF y enviar al comite (manual, tras revision).
 */
import { useEffect, useState } from 'react';
import { AxiosError } from 'axios';
import {
  FileText, Download, Send, Save, Loader2, Calendar, CheckCircle2, AlertTriangle,
} from 'lucide-react';
import { executiveApi, type ExecPreview, type ExecReportRef } from '@/lib/reports';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';

function thisMonth(): string {
  const n = new Date();
  return `${n.getFullYear()}-${String(n.getMonth() + 1).padStart(2, '0')}`;
}

const estadoBadge = (e: string) =>
  e === 'enviado' ? <Badge variant="success">enviado</Badge>
  : e === 'revisado' ? <Badge variant="default">revisado</Badge>
  : <Badge variant="muted">borrador</Badge>;

export function ExecutiveReports({ onFlash }: { onFlash: (k: 'ok' | 'err', t: string) => void }) {
  const [mes, setMes] = useState(thisMonth());
  const [current, setCurrent] = useState<ExecPreview | null>(null);
  const [resumen, setResumen] = useState('');
  const [recomendaciones, setRecomendaciones] = useState('');
  const [history, setHistory] = useState<ExecReportRef[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [confirmSend, setConfirmSend] = useState(false);

  const err = (e: unknown) =>
    onFlash('err', (e as AxiosError<{ error?: string }>).response?.data?.error ?? 'Error');

  async function loadHistory() {
    setHistory(await executiveApi.history().catch(() => []));
  }
  useEffect(() => { loadHistory(); }, []);

  function setPreview(p: ExecPreview) {
    setCurrent(p);
    setResumen(p.resumen);
    setRecomendaciones(p.recomendaciones);
  }

  async function generate() {
    setBusy('gen');
    try {
      setPreview(await executiveApi.generate(mes));
      await loadHistory();
      onFlash('ok', `Reporte de ${mes} generado (borrador)`);
    } catch (e) { err(e); } finally { setBusy(null); }
  }
  async function open(id: string) {
    setBusy('open');
    try { setPreview(await executiveApi.get(id)); } catch (e) { err(e); } finally { setBusy(null); }
  }
  async function saveDraft() {
    if (!current) return;
    setBusy('save');
    try {
      setPreview(await executiveApi.update(current.report.id, { resumen, recomendaciones }));
      await loadHistory();
      onFlash('ok', 'Cambios guardados (estado: revisado)');
    } catch (e) { err(e); } finally { setBusy(null); }
  }
  async function download() {
    if (!current) return;
    setBusy('dl');
    try { await executiveApi.download(current.report.id, current.report.mes); }
    catch { onFlash('err', 'No se pudo descargar'); } finally { setBusy(null); }
  }
  async function send() {
    if (!current) return;
    setBusy('send');
    try {
      const r = await executiveApi.send(current.report.id);
      setConfirmSend(false);
      onFlash('ok', `Enviado al comité (${r.recipients.length} destinatario(s))`);
      await open(current.report.id);
      await loadHistory();
    } catch (e) { err(e); setConfirmSend(false); } finally { setBusy(null); }
  }

  return (
    <div className="space-y-4">
      {/* Generador */}
      <Card>
        <CardHeader>
          <CardTitle className="text-muted-foreground">Reporte ejecutivo mensual · Comité SGSI</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap items-end gap-3">
            <div className="space-y-2">
              <Label>Mes (YYYY-MM)</Label>
              <Input type="month" value={mes} onChange={(e) => setMes(e.target.value)} className="w-44" />
            </div>
            <Button onClick={generate} disabled={busy === 'gen'}>
              {busy === 'gen' ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileText className="h-4 w-4" />}
              Generar reporte ejecutivo
            </Button>
            <span className="text-[11px] text-muted-foreground">
              Lenguaje de gestión · 8 secciones · alineado a ISO 27001 · revisión humana antes de enviar
            </span>
          </div>
        </CardContent>
      </Card>

      {/* Editor + Preview */}
      {current && (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0">
            <CardTitle className="flex items-center gap-2">
              <Calendar className="h-4 w-4" /> {current.report.mes} {estadoBadge(current.report.estado)}
            </CardTitle>
            <div className="flex flex-wrap gap-2">
              <Button variant="outline" size="sm" onClick={saveDraft} disabled={!!busy}>
                <Save className="h-4 w-4" /> Guardar
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
            {/* Campos editables */}
            <div className="grid gap-4 lg:grid-cols-2">
              <div className="space-y-2">
                <Label>Resumen ejecutivo (editable)</Label>
                <Textarea value={resumen} onChange={(e) => setResumen(e.target.value)} className="min-h-[120px]" />
              </div>
              <div className="space-y-2">
                <Label>Recomendaciones (editable)</Label>
                <Textarea value={recomendaciones} onChange={(e) => setRecomendaciones(e.target.value)} className="min-h-[120px]" />
              </div>
            </div>
            <p className="text-[11px] text-muted-foreground">
              Edita el texto y pulsa <b>Guardar</b> para regenerar el PDF con tus cambios antes de descargar o enviar.
            </p>

            {/* Previsualizacion */}
            <div>
              <Label className="mb-2 block">Previsualización del documento</Label>
              <iframe
                title="preview"
                srcDoc={current.html}
                className="h-[600px] w-full rounded-lg border border-border/60 bg-white"
              />
            </div>
          </CardContent>
        </Card>
      )}

      {/* Historial */}
      <Card>
        <CardHeader>
          <CardTitle className="text-muted-foreground">Historial de reportes ejecutivos ({history.length})</CardTitle>
        </CardHeader>
        <CardContent>
          {history.length === 0 ? (
            <p className="py-4 text-center text-sm text-muted-foreground">Aún no se han generado reportes ejecutivos.</p>
          ) : (
            <div className="space-y-2">
              {history.map((r) => (
                <div key={r.id} className="flex items-center gap-3 rounded-md border border-border/50 bg-card/40 px-3 py-2.5">
                  <Calendar className="h-4 w-4 text-muted-foreground" />
                  <span className="font-medium">{r.mes}</span>
                  {estadoBadge(r.estado)}
                  <span className="text-xs text-muted-foreground">
                    {r.generado_en ? new Date(r.generado_en).toLocaleString('es-CO') : ''}
                    {r.enviado_en ? ` · enviado ${new Date(r.enviado_en).toLocaleDateString('es-CO')}` : ''}
                  </span>
                  <Button variant="ghost" size="sm" className="ml-auto" onClick={() => open(r.id)}>Abrir</Button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Confirmacion de envio */}
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
                  Se enviará el reporte ejecutivo de <b>{current.report.mes}</b> con el PDF adjunto a los destinatarios configurados. ¿Confirmas el envío?
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
