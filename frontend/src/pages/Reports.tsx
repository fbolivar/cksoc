/**
 * Pagina de Reportes (Fase 4).
 * Generacion manual de reportes PDF, historial, descarga y borrado.
 * Informa del reporte programado (node-cron diario).
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
} from 'lucide-react';
import { useAuth } from '@/lib/auth';
import { reportsApi, type Report } from '@/lib/reports';
import type { TimeRange } from '@/lib/wazuh';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { ExecutiveReports } from '@/components/reports/ExecutiveReports';

export default function Reports() {
  const { user } = useAuth();
  const canManage = user?.role === 'admin' || user?.role === 'analista';
  const isAdmin = user?.role === 'admin';
  const [tab, setTab] = useState<'tecnico' | 'ejecutivo'>('tecnico');

  const [reports, setReports] = useState<Report[]>([]);
  const [title, setTitle] = useState('Reporte de seguridad HexWatch');
  const [range, setRange] = useState<TimeRange>('24h');
  const [generating, setGenerating] = useState(false);
  const [downloading, setDownloading] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  async function reload() {
    setReports(await reportsApi.list());
  }
  useEffect(() => {
    reload().catch(() => setMsg({ kind: 'err', text: 'No se pudo cargar el historial' }));
  }, []);

  const flash = (kind: 'ok' | 'err', text: string) => {
    setMsg({ kind, text });
    setTimeout(() => setMsg(null), 4000);
  };

  async function generate() {
    setGenerating(true);
    setMsg(null);
    try {
      await reportsApi.generate(title, range);
      await reload();
      flash('ok', 'Reporte generado correctamente');
    } catch (err) {
      flash('err', (err as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo generar el reporte');
    } finally {
      setGenerating(false);
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

  const pick = (title: string, r: TimeRange, exec?: boolean) => {
    if (exec && isAdmin) { setTab('ejecutivo'); return; }
    setTab('tecnico'); setTitle(title); setRange(r);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };
  const catalog: { icon: typeof FileText; col: string; title: string; desc: string; fmt: string; cadence: string; onClick: () => void }[] = [
    { icon: LineChart, col: 'primary', title: 'Resumen ejecutivo', desc: 'KPIs y tendencia de riesgo para dirección, sin tecnicismos.', fmt: 'PDF', cadence: 'Semanal', onClick: () => pick('Resumen ejecutivo HexWatch', '7d', true) },
    { icon: AlertTriangle, col: 'destructive', title: 'Vulnerabilidades priorizadas', desc: 'CVEs por riesgo real: CISA KEV + EPSS + CVSS.', fmt: 'PDF·CSV', cadence: 'Bajo demanda', onClick: () => pick('Vulnerabilidades priorizadas (KEV/EPSS)', '7d') },
    { icon: ClipboardCheck, col: 'cyan', title: 'Cumplimiento', desc: 'Estado frente a ISO 27001 / PCI. Brechas y evidencia.', fmt: 'PDF', cadence: 'Mensual', onClick: () => pick('Reporte de cumplimiento', '30d') },
    { icon: Timer, col: 'warn-orange', title: 'SLA & desempeño', desc: 'MTTA, MTTR y carga por analista del equipo.', fmt: 'PDF', cadence: 'Quincenal', onClick: () => pick('SLA y desempeño del SOC', '30d') },
    { icon: ShieldCheck, col: 'primary', title: 'Cobertura MITRE ATT&CK', desc: 'Técnicas detectadas vs. el marco. Puntos ciegos.', fmt: 'PDF', cadence: 'Mensual', onClick: () => pick('Cobertura MITRE ATT&CK', '30d') },
    { icon: ScrollText, col: 'success', title: 'Actividad & auditoría', desc: 'Bloqueos, aislamientos y accesos con trazabilidad.', fmt: 'PDF·CSV', cadence: 'Bajo demanda', onClick: () => pick('Actividad y auditoría del SOC', '7d') },
  ];

  return (
    <div className="mx-auto max-w-5xl space-y-5">
      <div>
        <h1 className="hw-mono flex items-center gap-2 text-2xl font-bold tracking-tight">
          <FileBarChart className="h-6 w-6 text-primary" /> REPORTES
        </h1>
        <p className="hw-mono text-[11px] tracking-wide text-muted-foreground">GENERA // PROGRAMA // DESCARGA</p>
      </div>

      {/* Catálogo de reportes */}
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
          Técnico
        </button>
        {isAdmin && (
          <button onClick={() => setTab('ejecutivo')}
            className={`px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors ${tab === 'ejecutivo' ? 'border-primary text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground'}`}>
            Ejecutivo (Comité SGSI)
          </button>
        )}
      </div>

      {tab === 'ejecutivo' && isAdmin && <ExecutiveReports onFlash={flash} />}

      {tab === 'tecnico' && (<>
      {/* Generador */}
      {canManage && (
        <Card>
          <CardHeader>
            <CardTitle className="text-muted-foreground">Generar reporte</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap items-end gap-3">
              <div className="flex-1 space-y-2" style={{ minWidth: 240 }}>
                <Label htmlFor="rtitle">Título</Label>
                <Input id="rtitle" value={title} onChange={(e) => setTitle(e.target.value)} />
              </div>
              <div className="space-y-2">
                <Label>Periodo</Label>
                <select
                  value={range}
                  onChange={(e) => setRange(e.target.value as TimeRange)}
                  className="h-10 rounded-md border border-input bg-background/60 px-3 text-sm"
                >
                  <option value="24h">Últimas 24 horas</option>
                  <option value="7d">Últimos 7 días</option>
                  <option value="30d">Últimos 30 días</option>
                </select>
              </div>
              <Button onClick={generate} disabled={generating || !title}>
                {generating ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileText className="h-4 w-4" />}
                {generating ? 'Generando…' : 'Generar PDF'}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Reporte programado */}
      <Card>
        <CardContent className="flex items-center gap-3 p-4">
          <CalendarClock className="h-5 w-5 text-neon" />
          <div className="text-sm">
            <p className="font-medium">Reporte programado</p>
            <p className="text-muted-foreground">
              Se genera automáticamente cada día a las 07:00 (últimas 24 h). Si hay SMTP configurado,
              se envía por correo a los destinatarios definidos.
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Historial */}
      <Card>
        <CardHeader>
          <CardTitle className="text-muted-foreground">Historial de reportes ({reports.length})</CardTitle>
        </CardHeader>
        <CardContent>
          {reports.length === 0 ? (
            <p className="py-6 text-center text-sm text-muted-foreground">
              No hay reportes todavía.
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
                      <td className="py-2.5 pr-4 text-muted-foreground">{r.params?.range ?? '—'}</td>
                      <td className="py-2.5">
                        <div className="flex justify-end gap-1">
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
    </div>
  );
}
