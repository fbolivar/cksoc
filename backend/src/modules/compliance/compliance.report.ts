/**
 * Informe de Cumplimiento Normativo (PDF con marca). Combina:
 *   - Cobertura de monitoreo por marco (getCompliance) priorizada por aplicabilidad.
 *   - Postura de configuración real CIS/SCA (getSca).
 * Reutiliza el motor htmlToPdf (Puppeteer) y la identidad de los informes del SOC.
 * HONESTO: mide cobertura de monitoreo + postura técnica, NO es una certificación;
 * la capa legal/organizacional (RNBD, autorizaciones, política de tratamiento) se
 * gestiona por fuera del SIEM.
 */
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { getCompliance } from './compliance.service';
import { getSca } from '../sca/sca.service';
import { htmlToPdf } from '../reports/pdf.service';
import { env } from '../../config/env';

const C = { tinta: '#16181d', texto: '#31363f', suave: '#6b7280', linea: '#e4e7ec', fondo: '#f7f8fa', marca: '#f0512e', marcaOsc: '#b8371a', ok: '#15803d', warn: '#b45309', crit: '#b91c1c', head: '#1f2937' };

const esc = (s: unknown): string => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const fmt = (n: number): string => n.toLocaleString('es-CO');

function logoDataUri(): string | undefined {
  for (const p of [resolve(process.cwd(), '../frontend/public/logo-pnnc.png'), resolve(process.cwd(), 'assets/logo-pnnc.png')]) {
    if (existsSync(p)) return `data:image/png;base64,${readFileSync(p).toString('base64')}`;
  }
  return undefined;
}

type Aplica = 'si' | 'opcional' | 'no';
interface Meta { label: string; aplica: Aplica; catalogo: number; nota: string }
const META: Record<string, Meta> = {
  ley1581: { label: 'Ley 1581 (Habeas Data)', aplica: 'si', catalogo: 6, nota: 'Obligatoria (SIC). Evidencia técnica directa por tipo de evento.' },
  iso27001: { label: 'ISO/IEC 27001:2022', aplica: 'si', catalogo: 15, nota: 'Sello comercial. Anexo A derivado por crosswalk desde NIST.' },
  gdpr: { label: 'GDPR', aplica: 'opcional', catalogo: 8, nota: 'Aplica si hay titulares de datos en la Unión Europea.' },
  nist: { label: 'NIST 800-53', aplica: 'si', catalogo: 20, nota: 'Catálogo técnico base; respaldo de ISO y Ley 1581.' },
  tsc: { label: 'SOC 2 (TSC)', aplica: 'opcional', catalogo: 12, nota: 'A demanda, si un cliente lo exige.' },
  pci: { label: 'PCI DSS', aplica: 'no', catalogo: 12, nota: 'No aplica: no procesa pagos con tarjeta.' },
  hipaa: { label: 'HIPAA', aplica: 'no', catalogo: 10, nota: 'No aplica: no es entidad de salud de EE. UU.' },
};
const APL: Record<Aplica, { t: string; c: string }> = { si: { t: 'Aplica', c: C.ok }, opcional: { t: 'Condicional', c: C.warn }, no: { t: 'No aplica', c: C.suave } };

const CONTROL_DESC: Record<string, string> = {
  'L.SEG': 'Medidas de seguridad y control de acceso (Art. 4.g · Decreto 1074)',
  'L.CIFR': 'Confidencialidad de las comunicaciones', 'L.TRAZ': 'Trazabilidad y registro de accesos',
  'L.DET': 'Detección y reporte de incidentes a la SIC (Art. 17.n)', 'L.INTEG': 'Integridad y calidad del dato (Art. 4.d)',
  'L.VULN': 'Gestión de vulnerabilidades técnicas',
  'A.5.15': 'Control de acceso', 'A.5.17': 'Información de autenticación', 'A.8.2': 'Derechos de acceso privilegiado',
  'A.8.5': 'Autenticación segura', 'A.8.7': 'Protección contra malware', 'A.8.8': 'Gestión de vulnerabilidades técnicas',
  'A.8.9': 'Gestión de la configuración', 'A.8.15': 'Registro de eventos (logging)', 'A.8.16': 'Actividades de monitoreo',
  'A.8.20': 'Seguridad de las redes', 'A.8.22': 'Segregación de redes', 'A.8.24': 'Uso de criptografía',
  'A.8.25': 'Desarrollo seguro', 'A.8.29': 'Pruebas de seguridad', 'A.8.32': 'Gestión de cambios',
  'IV_32.2': 'Seguridad del tratamiento (Art. 32.2)', 'IV_35.7.d': 'Evaluación de impacto (Art. 35.7.d)', 'II_5.1.f': 'Integridad y confidencialidad (Art. 5.1.f)',
};
const desc = (id: string): string => CONTROL_DESC[id] ?? 'Control del marco';
const pct = (cub: number, cat: number): number => Math.min(100, Math.round((cub / cat) * 100));
const pctColor = (p: number): string => (p >= 66 ? C.ok : p >= 33 ? C.warn : C.crit);

function h2(t: string): string {
  return `<h2 style="font-size:14pt;color:${C.tinta};margin:20px 0 6px;padding:0 0 5px;border-bottom:2px solid ${C.marca};page-break-after:avoid;font-family:'Space Grotesk',sans-serif;font-weight:700">${esc(t)}</h2>`;
}
function h3(t: string): string {
  return `<h3 style="font-size:11.5pt;color:${C.tinta};margin:14px 0 4px;font-family:'Space Grotesk',sans-serif;font-weight:700">${esc(t)}</h3>`;
}
function p(txt: string): string {
  return `<p style="font-size:10pt;line-height:1.55;color:${C.texto};margin:0 0 7px;text-align:justify">${txt}</p>`;
}
function tabla(cols: string[], rows: string[][], anchos?: string[]): string {
  if (!rows.length) return `<p style="font-size:9.5pt;color:${C.suave};margin:2px 0 8px"><i>Sin datos en el periodo.</i></p>`;
  const th = cols.map((c, i) => `<th style="text-align:left;padding:5px 8px;background:${C.head};color:#fff;font-size:8.5pt;${anchos?.[i] ? 'width:' + anchos[i] : ''}">${esc(c)}</th>`).join('');
  const tr = rows.map((r, ri) => `<tr style="background:${ri % 2 ? C.fondo : '#fff'}">${r.map((c) => `<td style="padding:4px 8px;border-bottom:1px solid ${C.linea};font-size:9pt;color:${C.tinta};vertical-align:top">${c}</td>`).join('')}</tr>`).join('');
  return `<table style="width:100%;border-collapse:collapse;margin:3px 0 10px;page-break-inside:avoid"><thead><tr>${th}</tr></thead><tbody>${tr}</tbody></table>`;
}
const chip = (t: string, color: string): string => `<span style="display:inline-block;padding:1px 7px;border-radius:9px;font-size:8pt;font-weight:700;color:#fff;background:${color}">${esc(t)}</span>`;

export async function complianceReportPdf(hours: number): Promise<{ buffer: Buffer; filename: string }> {
  const [comp, sca] = await Promise.all([getCompliance(hours), getSca()]);
  const cliente = env.REPORT_CLIENT_NAME || 'la organización';
  const dias = Math.round(hours / 24);
  const hoy = new Date().toLocaleDateString('es-CO', { timeZone: 'America/Bogota', day: '2-digit', month: 'long', year: 'numeric' });
  const logo = logoDataUri();
  const orden = ['ley1581', 'iso27001', 'gdpr', 'nist', 'tsc', 'pci', 'hipaa'];
  const detalle = ['ley1581', 'iso27001', 'gdpr'];
  const out: string[] = [];

  // --- Resumen de aplicabilidad ---
  out.push(h2('1. Alcance y aplicabilidad'));
  out.push(p(`Este informe resume la <b>cobertura de monitoreo de seguridad</b> de ${esc(cliente)} frente a los marcos normativos, priorizados según lo que le aplica a la organización, y la <b>postura de configuración técnica (CIS)</b> de sus equipos. Periodo analizado: <b>últimos ${dias} días</b>.`));
  out.push(tabla(['Marco', 'Aplicabilidad', 'Cobertura técnica', 'Controles con monitoreo', 'Observación'],
    orden.filter((k) => comp.frameworks[k]).map((k) => {
      const f = comp.frameworks[k]!; const m = META[k]!; const pc = pct(f.controlesCubiertos, m.catalogo);
      return [esc(m.label), chip(APL[m.aplica].t, APL[m.aplica].c), `<b style="color:${pctColor(pc)}">${pc}%</b>`, `${f.controlesCubiertos} / ${m.catalogo}`, esc(m.nota)];
    }), ['24%', '13%', '13%', '16%', '34%']));
  out.push(`<div style="border-left:3px solid ${C.marca};background:${C.fondo};padding:9px 12px;border-radius:4px;margin:4px 0 2px"><p style="font-size:9pt;line-height:1.5;color:${C.texto};margin:0">⚠ <b>Qué es y qué no es este informe.</b> Mide <b>cobertura de monitoreo</b> (cuántos controles técnicos de cada marco están vigilados por alertas reales) y <b>postura de configuración</b> (CIS/SCA). <b>No es una certificación de cumplimiento</b>: el cierre legal de la Ley 1581 o de ISO 27001 requiere, además, los procesos organizacionales —registro de bases de datos ante la SIC (RNBD), autorizaciones de titulares, política de tratamiento, respuesta a derechos— y una auditoría formal, que no se detectan por registros técnicos.</p></div>`);

  // --- Detalle por marco aplicable ---
  out.push(h2('2. Marcos aplicables — cobertura por control'));
  for (const k of detalle) {
    const f = comp.frameworks[k]; const m = META[k]; if (!f || !m) continue;
    const pc = pct(f.controlesCubiertos, m.catalogo);
    out.push(h3(`${m.label} — ${pc}% de cobertura técnica (${f.controlesCubiertos} de ${m.catalogo} controles · ${fmt(f.total)} eventos)`));
    out.push(tabla(['Control', 'Descripción', 'Severidad máx.', 'Eventos'],
      f.controles.slice(0, 12).map((c) => [esc(c.id), esc(desc(c.id)), c.level >= 8 ? chip('N' + c.level, c.level >= 12 ? C.crit : C.warn) : 'N' + c.level, fmt(c.count)]),
      ['16%', '52%', '16%', '16%']));
  }
  out.push(`<p style="font-size:8.5pt;color:${C.suave};margin:0 0 4px"><i>Ley 1581: evidencia directa por tipo de evento (acceso, trazabilidad, detección, integridad/FIM, vulnerabilidades, comunicaciones). ISO 27001: Anexo A derivado por crosswalk desde los controles técnicos de NIST que Wazuh etiqueta.</i></p>`);

  // --- Postura de configuración CIS/SCA ---
  const r = sca.resumen;
  const scorePc = Math.round(r.scorePromedio);
  out.push(h2('3. Postura de configuración técnica (CIS / Hardening)'));
  out.push(p(`La cobertura de monitoreo indica qué se vigila; la <b>postura CIS</b> indica si los equipos están <b>configurados al estándar</b>. Sobre <b>${r.agentesEvaluados} equipo(s) evaluado(s)</b> (${r.agentesActivos} activos), el cumplimiento promedio de configuración segura es <b style="color:${pctColor(scorePc)}">${scorePc}%</b>, con <b>${fmt(r.pass)} verificaciones aprobadas</b> y <b>${fmt(r.fail)} fallidas</b> (${r.failAlto} tipos de alto impacto). ${r.activosSinSca.length ? `<b>${r.activosSinSca.length} activo(s) sin evaluación de hardening</b> (punto ciego): ${esc(r.activosSinSca.slice(0, 6).join(', '))}.` : 'Todos los activos activos tienen evaluación de hardening.'}`));
  out.push(tabla(['Equipo', 'Sistema', 'Política', 'Config. segura', 'Aprob./Fall.'],
    sca.agentes.slice(0, 10).map((a) => [esc(a.agent), esc(a.os), esc(a.policy).slice(0, 34), `<b style="color:${pctColor(a.score)}">${a.score}%</b>`, `${fmt(a.pass)} / ${fmt(a.fail)}`]),
    ['22%', '16%', '30%', '16%', '16%']));
  if (sca.topFallidos.length) {
    out.push(h3('Controles de configuración fallidos más frecuentes (alto impacto primero)'));
    out.push(tabla(['Impacto', 'Control CIS', 'Equipos', 'Remediación'],
      sca.topFallidos.slice(0, 8).map((c) => [chip(c.impact, c.impact === 'alto' ? C.crit : c.impact === 'medio' ? C.warn : C.suave), esc(c.title).slice(0, 70), fmt(c.count), esc(c.remediation).slice(0, 80)]),
      ['12%', '40%', '12%', '36%']));
  }

  // --- Nota metodológica ---
  out.push(h2('4. Nota metodológica'));
  out.push(p('Los conteos provienen de la plataforma de monitoreo (Wazuh) y excluyen el ruido benigno del sistema operativo y de la red para no distorsionar la evidencia. La Ley 1581 se mide con consultas directas por control; ISO 27001 se deriva por crosswalk de los controles técnicos de NIST 800-53; GDPR converge técnicamente con la Ley 1581. PCI DSS e HIPAA no aplican a la organización y se conservan solo como referencia. La postura CIS proviene de la evaluación de configuración (SCA) de los agentes.'));
  out.push(p('<b>Recomendación de uso:</b> este informe es insumo técnico para el responsable de tratamiento de datos y para una eventual auditoría; debe acompañarse de la documentación organizacional del programa de protección de datos y de seguridad de la información.'));

  const contenido = out.join('\n');
  const html = `<!doctype html><html lang="es"><head><meta charset="utf-8">
<style>
  @page { margin: 0; size: A4; }
  @page:first { margin: 0; }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: 'Space Grotesk', system-ui, sans-serif; color: ${C.tinta}; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .cover { height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center;
           background: linear-gradient(155deg, #141518 0%, #24262c 55%, ${C.marcaOsc} 190%); color: #fff; page-break-after: always; padding: 0 40px; }
  .cover img { height: 58px; background: #fff; padding: 7px 10px; border-radius: 8px; margin-bottom: 24px; }
  .content { padding: 30px 40px 48px; }
  .footer-band { position: fixed; bottom: 0; left: 0; right: 0; background: ${C.tinta}; color: #c9cdd4; font-size: 8pt;
                 padding: 6px 40px; display: flex; justify-content: space-between; }
</style></head><body>
  <div class="cover">
    ${logo ? `<img src="${logo}" alt="SOC">` : ''}
    <div style="font-size:11pt;letter-spacing:3px;color:#cbd5e1;text-transform:uppercase">Informe de</div>
    <h1 style="font-size:26pt;margin:10px 0 8px;font-weight:700;line-height:1.25;font-family:'Space Grotesk',sans-serif">Cumplimiento Normativo</h1>
    <div style="width:64px;height:3px;background:${C.marca};margin:12px 0 16px"></div>
    <div style="font-size:17pt;color:#fff;font-weight:700;margin-bottom:6px">${esc(cliente)}</div>
    <div style="font-size:10.5pt;color:#cbd5e1">Periodo: últimos ${dias} días &nbsp;·&nbsp; ${esc(hoy)}</div>
    <div style="margin-top:22px;font-size:9pt;color:#94a3b8;max-width:430px">Cobertura de monitoreo frente a Ley 1581, ISO/IEC 27001 y GDPR, y postura de configuración CIS. Documento confidencial.</div>
  </div>
  <div class="content">${contenido}</div>
  <div class="footer-band"><span>Informe de Cumplimiento Normativo — ${esc(cliente)}</span><span>Confidencial · ${esc(hoy)}</span></div>
</body></html>`;

  const buffer = await htmlToPdf(html, { cssPage: true });
  const safe = String(cliente).replace(/[^\w.-]+/g, '_').slice(0, 40);
  const filename = `Informe-Cumplimiento-${safe}-${new Date().toISOString().slice(0, 10)}.pdf`;
  return { buffer, filename };
}
