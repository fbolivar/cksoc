/**
 * Plantilla HTML del reporte PDF con identidad PNNC.
 * Diseno claro/institucional (mejor para impresion) con encabezado GOV.CO.
 */
import type { ReportData } from './report.data';
import { donutSvg, barsSvg, sparkAreaSvg } from './svg';

const fmt = (n: number) => n.toLocaleString('es-CO');

const RANGE_LABELS: Record<string, string> = {
  '24h': 'Últimas 24 horas',
  '7d': 'Últimos 7 días',
  '30d': 'Últimos 30 días',
};

const SEV = {
  baja: { label: 'Baja', color: '#16a34a' },
  media: { label: 'Media', color: '#eab308' },
  alta: { label: 'Alta', color: '#f97316' },
  critica: { label: 'Crítica', color: '#ef4444' },
};

export function buildReportHtml(
  data: ReportData,
  opts: { title: string; logoDataUri?: string }
): string {
  const { summary, timeline, topAgents, mitre, agents } = data;
  const rangeLabel = RANGE_LABELS[data.range] ?? data.range;
  const fecha = new Date(data.generatedAt).toLocaleString('es-CO');

  const donut = donutSvg(
    (Object.keys(SEV) as (keyof typeof SEV)[]).map((k) => ({
      label: SEV[k].label,
      value: summary.byBand[k],
      color: SEV[k].color,
    }))
  );
  const agentsBars = barsSvg(topAgents.map((a) => ({ label: a.agent, value: a.count })), '#1f7a4d');
  const mitreBars = mitre.length
    ? barsSvg(mitre.map((m) => ({ label: m.technique, value: m.count })), '#7c3aed')
    : '<p style="color:#888;font-size:12px">Sin técnicas MITRE en el periodo</p>';
  const spark = sparkAreaSvg(timeline);

  const sevRows = (Object.keys(SEV) as (keyof typeof SEV)[])
    .map(
      (k) => `<tr>
        <td><span class="dot" style="background:${SEV[k].color}"></span>${SEV[k].label}</td>
        <td class="num">${fmt(summary.byBand[k])}</td>
        <td class="num">${((summary.byBand[k] / (summary.total || 1)) * 100).toFixed(1)}%</td>
      </tr>`
    )
    .join('');

  return `<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<style>
  * { box-sizing: border-box; }
  body { font-family: 'Liberation Sans', Arial, sans-serif; color: #1f2a26; margin: 0; font-size: 12px; }
  .header { background: #16294f; color: #fff; padding: 18px 28px; border-bottom: 4px solid #1f7a4d; display: flex; align-items: center; gap: 14px; }
  .header img { height: 46px; background:#fff; border-radius:6px; padding:3px; }
  .header h1 { font-size: 16px; margin: 0; }
  .header p { font-size: 11px; margin: 2px 0 0; color: #c5d2ea; }
  .content { padding: 24px 28px; }
  .title { font-size: 20px; font-weight: 700; color: #0f3d24; margin: 0 0 2px; }
  .subtitle { color: #5b6b63; margin: 0 0 18px; }
  .kpis { display: flex; gap: 12px; margin-bottom: 22px; }
  .kpi { flex: 1; border: 1px solid #e2e8e4; border-radius: 8px; padding: 12px 14px; }
  .kpi .v { font-size: 22px; font-weight: 800; }
  .kpi .l { font-size: 10px; color: #6b7c74; text-transform: uppercase; letter-spacing: .04em; }
  .grid2 { display: flex; gap: 20px; margin-bottom: 22px; }
  .card { border: 1px solid #e2e8e4; border-radius: 8px; padding: 14px 16px; }
  .card h3 { font-size: 12px; margin: 0 0 10px; color: #0f3d24; text-transform: uppercase; letter-spacing: .04em; }
  table.data { width: 100%; border-collapse: collapse; font-size: 11px; }
  table.data td, table.data th { padding: 5px 6px; border-bottom: 1px solid #eef2ef; text-align: left; }
  table.data .num { text-align: right; font-variant-numeric: tabular-nums; }
  .dot { display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:6px;vertical-align:middle; }
  .footer { padding: 12px 28px; border-top: 1px solid #e2e8e4; color: #8a978f; font-size: 10px; display:flex; justify-content:space-between; }
  .section-title { font-size: 13px; font-weight:700; color:#0f3d24; margin: 4px 0 10px; }
</style></head>
<body>
  <div class="header">
    ${opts.logoDataUri ? `<img src="${opts.logoDataUri}" alt="PNNC">` : ''}
    <div>
      <h1>Centro de Operaciones de Seguridad · PNNC</h1>
      <p>Parques Nacionales Naturales de Colombia · GOV.CO</p>
    </div>
  </div>

  <div class="content">
    <p class="title">${escapeHtml(opts.title)}</p>
    <p class="subtitle">${rangeLabel} · Generado el ${fecha}</p>

    <div class="kpis">
      <div class="kpi"><div class="v">${fmt(summary.total)}</div><div class="l">Alertas totales</div></div>
      <div class="kpi"><div class="v" style="color:#f97316">${fmt(summary.byBand.alta + summary.byBand.critica)}</div><div class="l">Alta + Crítica</div></div>
      <div class="kpi"><div class="v" style="color:#ef4444">${fmt(summary.byBand.critica)}</div><div class="l">Críticas</div></div>
      <div class="kpi"><div class="v" style="color:#1f7a4d">${agents ? `${agents.active}/${agents.total}` : '—'}</div><div class="l">Agentes activos</div></div>
    </div>

    <div class="section-title">Tendencia de alertas</div>
    <div class="card" style="margin-bottom:22px">${spark}</div>

    <div class="grid2">
      <div class="card" style="flex:0 0 240px;text-align:center">
        <h3>Por severidad</h3>
        ${donut}
        <table class="data" style="margin-top:10px">${sevRows}</table>
      </div>
      <div class="card" style="flex:1">
        <h3>Top agentes por alertas</h3>
        ${agentsBars}
      </div>
    </div>

    <div class="card" style="margin-bottom:22px">
      <h3>Top técnicas MITRE ATT&CK</h3>
      ${mitreBars}
    </div>

    ${agents ? `<div class="card">
      <h3>Estado de agentes</h3>
      <table class="data">
        <tr><td>Activos</td><td class="num">${agents.active}</td></tr>
        <tr><td>Desconectados</td><td class="num">${agents.disconnected}</td></tr>
        <tr><td>Nunca conectados</td><td class="num">${agents.neverConnected}</td></tr>
        <tr><td>Pendientes</td><td class="num">${agents.pending}</td></tr>
        <tr><td><b>Total</b></td><td class="num"><b>${agents.total}</b></td></tr>
      </table>
    </div>` : ''}
  </div>

  <div class="footer">
    <span>SOC PNNC · Documento generado automáticamente</span>
    <span>Confidencial · Uso interno</span>
  </div>
</body></html>`;
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
