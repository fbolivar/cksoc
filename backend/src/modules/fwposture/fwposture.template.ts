/** Plantilla HTML del reporte de postura del SonicWall (vista previa + PDF A4). */
import type { FwPosture } from './fwposture.service';
import type { Check, Estado, Sev } from './fwposture.checks';

const esc = (s: string): string => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c] as string));

const EST: Record<Estado, { label: string; color: string; bg: string }> = {
  fail: { label: 'INCUMPLE', color: '#DC2626', bg: '#FBE9E9' },
  warn: { label: 'REVISAR', color: '#B45309', bg: '#FBF1E0' },
  pass: { label: 'OK', color: '#12813F', bg: '#E7F5EC' },
  na: { label: 'S/D', color: '#6B7280', bg: '#F1F2F4' },
};
const SEV: Record<Sev, string> = { alta: '#DC2626', media: '#D97706', baja: '#6B7280' };

function gradeOf(score: number): { g: string; color: string } {
  if (score >= 90) return { g: 'A', color: '#12813F' };
  if (score >= 75) return { g: 'B', color: '#4D7C0F' };
  if (score >= 60) return { g: 'C', color: '#B45309' };
  if (score >= 40) return { g: 'D', color: '#EA580C' };
  return { g: 'E', color: '#DC2626' };
}

/** Render mínimo de la narrativa IA: **negrita** + viñetas, preservando saltos. */
function richText(t: string): string {
  const lines = esc(t).split('\n');
  const out: string[] = [];
  for (const raw of lines) {
    const line = raw.replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>');
    const l = line.trim();
    if (!l) { out.push('<div style="height:6px"></div>'); continue; }
    if (/^[-*]\s+/.test(l)) out.push(`<div style="display:flex;gap:7px;padding-left:4px"><span style="color:#F0512E">•</span><span>${l.replace(/^[-*]\s+/, '')}</span></div>`);
    else out.push(`<div>${line}</div>`);
  }
  return out.join('');
}

function checkRow(c: Check): string {
  const e = EST[c.estado];
  return `<tr>
    <td style="padding:7px 9px;border-bottom:1px solid #ECEEF2;vertical-align:top">
      <div style="font-weight:600;font-size:11.5px">${esc(c.titulo)}</div>
      <div style="font-size:10px;color:#697086;margin-top:2px">${esc(c.evidencia)}</div>
      <div style="font-size:9px;color:#9AA0B0;margin-top:3px">↳ ${esc(c.remediacion)}</div>
    </td>
    <td style="padding:7px 9px;border-bottom:1px solid #ECEEF2;vertical-align:top;white-space:nowrap">
      <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${SEV[c.severidad]};margin-right:4px"></span>
      <span style="font-size:10px;text-transform:capitalize;color:#697086">${c.severidad}</span>
    </td>
    <td style="padding:7px 9px;border-bottom:1px solid #ECEEF2;vertical-align:top;text-align:center;white-space:nowrap">
      <span style="font-size:9.5px;font-weight:700;color:${e.color};background:${e.bg};padding:2px 7px;border-radius:999px">${e.label}</span>
    </td></tr>`;
}

export function buildFwPostureHtml(p: FwPosture): string {
  const { g, color } = gradeOf(p.resumen.score);
  const d = p.device;
  const orden: Record<Estado, number> = { fail: 0, warn: 1, na: 2, pass: 3 };
  const sevRank: Record<Sev, number> = { alta: 0, media: 1, baja: 2 };
  const checks = [...p.checks].sort((a, b) => orden[a.estado] - orden[b.estado] || sevRank[a.severidad] - sevRank[b.severidad]);
  const fecha = new Date(p.generatedAt).toLocaleString('es-CO', { dateStyle: 'long', timeStyle: 'short' });

  return `<!doctype html><html lang="es"><head><meta charset="utf-8">
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Inter Tight',system-ui,Arial,sans-serif;color:#191C22;background:#fff;line-height:1.5;-webkit-print-color-adjust:exact;print-color-adjust:exact}
  .wrap{max-width:820px;margin:0 auto;padding:26px 30px}
  .head{display:flex;align-items:center;gap:12px;border-bottom:3px solid #F0512E;padding-bottom:12px}
  .head h1{font-size:19px;letter-spacing:-.01em}
  .head .sub{font-size:11px;color:#697086;margin-top:2px}
  .badge{margin-left:auto;text-align:center}
  .badge .g{font-size:40px;font-weight:800;line-height:1}
  .badge .s{font-size:10px;color:#697086}
  h2{font-size:14px;margin:22px 0 9px;padding-bottom:5px;border-bottom:1px solid #E6E8EF;color:#191C22}
  .kpis{display:flex;gap:10px;margin:14px 0}
  .kpi{flex:1;border:1px solid #E6E8EF;border-radius:9px;padding:11px 13px}
  .kpi .n{font-size:24px;font-weight:800;font-variant-numeric:tabular-nums}
  .kpi .l{font-size:10px;color:#697086;margin-top:2px}
  table{width:100%;border-collapse:collapse}
  .ia{font-size:11.5px;color:#20242c;background:#FAFBFC;border:1px solid #E6E8EF;border-radius:9px;padding:13px 15px}
  .meta{font-size:10px;color:#697086}
  .foot{margin-top:20px;border-top:1px solid #E6E8EF;padding-top:9px;font-size:10px;color:#9AA0B0}
</style></head><body><div class="wrap">
  <div class="head">
    <div>
      <h1>Postura de Seguridad · Firewall</h1>
      <div class="sub">${esc(d.hostname)}${d.model ? ` · ${esc(d.model)}` : ''}${d.version ? ` · SonicOS ${esc(d.version)}` : ''}${d.serial ? ` · ${esc(d.serial)}` : ''}</div>
    </div>
    <div class="badge"><div class="g" style="color:${color}">${g}</div><div class="s">${p.resumen.score}/100</div></div>
  </div>

  <div class="kpis">
    <div class="kpi"><div class="n" style="color:#DC2626">${p.resumen.fail}</div><div class="l">Incumplimientos</div></div>
    <div class="kpi"><div class="n" style="color:#B45309">${p.resumen.warn}</div><div class="l">A revisar</div></div>
    <div class="kpi"><div class="n" style="color:#12813F">${p.resumen.pass}</div><div class="l">Conformes</div></div>
    <div class="kpi"><div class="n" style="color:#6B7280">${p.resumen.na}</div><div class="l">Sin dato</div></div>
  </div>

  <h2>Análisis del auditor</h2>
  ${p.ia ? `<div class="ia">${richText(p.ia)}</div>` : `<div class="ia meta">Análisis con IA no disponible (Copiloto sin configurar). El informe presenta los checks deterministas y el Security Rating de SonicWall.</div>`}

  <h2>Controles evaluados (${p.checks.length})</h2>
  <table>
    <thead><tr>
      <th style="text-align:left;font-size:9.5px;color:#697086;padding:0 9px 6px">Control · evidencia · remediación</th>
      <th style="text-align:left;font-size:9.5px;color:#697086;padding:0 9px 6px">Severidad</th>
      <th style="text-align:center;font-size:9.5px;color:#697086;padding:0 9px 6px">Estado</th>
    </tr></thead>
    <tbody>${checks.map(checkRow).join('')}</tbody>
  </table>

  <p class="meta" style="margin-top:12px">Controles alineados a las mejores prácticas de hardening de SonicWall (hardening SonicWall). El puntaje pondera conformes (100%) y a-revisar (50%) sobre los controles evaluables. Complementa —no reemplaza— el Security Rating nativo de SonicWall.</p>

  <div class="foot">Generado por HexWatch · ${esc(fecha)} · Datos leídos en solo-lectura de la API del SonicWall. No se incluyen secretos (contraseñas, llaves).</div>
</div></body></html>`;
}
