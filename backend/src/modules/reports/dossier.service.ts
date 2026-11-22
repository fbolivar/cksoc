/**
 * DOSIER DE AUDITORÍA (todo en uno). Genera un único PDF que reúne, en orden:
 *   Portada + índice del dosier
 *   Parte I   — Informe Gerencial de Seguridad
 *   Parte II  — Informe de Cumplimiento Normativo (Ley 1581 / ISO 27001 + postura CIS)
 *   Parte III — Informe Técnico de Operaciones (anexo, opcional)
 *
 * Reutiliza los servicios de cada informe SIN modificarlos y une los PDF con
 * `pdfunite` (poppler). Pensado como entregable único ante una auditoría.
 */
import { readFileSync, existsSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { resolvePeriodo, PeriodoInvalido, fechaLarga, type Periodo } from './executive/periodo';
import { collectMetrics } from './executive/exec.data';
import { buildExecutiveHtml } from './executive/exec.template';
import { collectTechMetrics } from './tecnico/tech.data';
import { buildTechnicalHtml } from './tecnico/tech.template';
import { complianceReportPdf } from '../compliance/compliance.report';
import { htmlToPdf } from './pdf.service';
import { env } from '../../config/env';
import { HttpError } from '../auth/auth.service';

const ORG = process.env.REPORT_ORG_NAME?.trim() || env.REPORT_CLIENT_NAME || 'la organización';
const C = { marca: '#f0512e', marcaOsc: '#b8371a', tinta: '#16181d', texto: '#31363f', suave: '#6b7280', linea: '#e4e7ec', fondo: '#f7f8fa' };

const esc = (s: unknown): string => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

function logoDataUri(): string | undefined {
  for (const p of [resolve(process.cwd(), '../frontend/public/logo-pnnc.png'), resolve(process.cwd(), 'assets/logo-pnnc.png')]) {
    if (existsSync(p)) return `data:image/png;base64,${readFileSync(p).toString('base64')}`;
  }
  return undefined;
}

/** Portada + índice del dosier. */
function portadaHtml(cliente: string, periodo: Periodo, partes: { n: string; t: string; d: string }[]): string {
  const logo = logoDataUri();
  const hoy = fechaLarga(new Date().toISOString());
  const indice = partes.map((p) => `
    <div style="display:flex;gap:12px;padding:12px 14px;border:1px solid ${C.linea};border-left:3px solid ${C.marca};border-radius:5px;margin-bottom:9px;page-break-inside:avoid">
      <div style="font-family:'Space Grotesk',sans-serif;font-weight:700;font-size:15pt;color:${C.marca};min-width:34px">${esc(p.n)}</div>
      <div><div style="font-weight:700;font-size:11.5pt;color:${C.tinta}">${esc(p.t)}</div>
      <div style="font-size:9.5pt;color:${C.suave};margin-top:2px">${esc(p.d)}</div></div>
    </div>`).join('');
  return `<!doctype html><html lang="es"><head><meta charset="utf-8"><style>
    @page { margin: 0; size: A4; } * { box-sizing: border-box; }
    body { margin:0; font-family:'Space Grotesk',system-ui,sans-serif; color:${C.tinta}; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
    .cover { height:100vh; display:flex; flex-direction:column; justify-content:center; align-items:center; text-align:center;
             background:linear-gradient(155deg,#141518 0%,#24262c 55%,${C.marcaOsc} 190%); color:#fff; page-break-after:always; padding:0 40px; }
    .cover img { height:58px; background:#fff; padding:7px 10px; border-radius:8px; margin-bottom:24px; }
    .content { padding:38px 44px; }
  </style></head><body>
    <div class="cover">
      ${logo ? `<img src="${logo}" alt="SOC">` : ''}
      <div style="font-size:11pt;letter-spacing:3px;color:#cbd5e1;text-transform:uppercase">Dosier de</div>
      <h1 style="font-size:27pt;margin:10px 0 8px;font-weight:700;line-height:1.2">Auditoría de Seguridad<br>de la Información</h1>
      <div style="width:64px;height:3px;background:${C.marca};margin:12px 0 16px"></div>
      <div style="font-size:17pt;font-weight:700;margin-bottom:6px">${esc(cliente)}</div>
      <div style="font-size:10.5pt;color:#cbd5e1">${esc(periodo.rangoTexto)}</div>
      <div style="margin-top:22px;font-size:9pt;color:#94a3b8;max-width:440px">Expediente único de evidencia para auditoría interna o externa: gestión gerencial, cumplimiento normativo y detalle técnico de operaciones. Documento confidencial.</div>
    </div>
    <div class="content">
      <h2 style="font-size:15pt;color:${C.tinta};margin:0 0 4px;padding:0 0 6px;border-bottom:2px solid ${C.marca};font-family:'Space Grotesk',sans-serif;font-weight:700">Contenido del dosier</h2>
      <p style="font-size:10pt;line-height:1.55;color:${C.texto};margin:8px 0 14px;text-align:justify">Este dosier reúne, en un solo documento, los informes que sustentan la operación del servicio de seguridad gestionado para <b>${esc(cliente)}</b> durante el periodo <b>${esc(periodo.rangoTexto)}</b>. Cada parte conserva su portada y puede leerse de forma independiente.</p>
      ${indice}
      <table style="width:100%;border-collapse:collapse;margin:16px 0 0">
        <tr><td style="padding:5px 8px;font-size:9.5pt;color:${C.suave};width:38%">Organización evaluada</td><td style="padding:5px 8px;font-size:9.5pt;color:${C.tinta};font-weight:700">${esc(cliente)}</td></tr>
        <tr style="background:${C.fondo}"><td style="padding:5px 8px;font-size:9.5pt;color:${C.suave}">Periodo</td><td style="padding:5px 8px;font-size:9.5pt;color:${C.tinta}">${esc(periodo.rangoTexto)} (${periodo.dias} días)</td></tr>
        <tr><td style="padding:5px 8px;font-size:9.5pt;color:${C.suave}">Emitido</td><td style="padding:5px 8px;font-size:9.5pt;color:${C.tinta}">${esc(hoy)}</td></tr>
        <tr style="background:${C.fondo}"><td style="padding:5px 8px;font-size:9.5pt;color:${C.suave}">Elaborado por</td><td style="padding:5px 8px;font-size:9.5pt;color:${C.tinta}">Centro de Operaciones de Seguridad — HexWatch</td></tr>
        <tr><td style="padding:5px 8px;font-size:9.5pt;color:${C.suave}">Clasificación</td><td style="padding:5px 8px;font-size:9.5pt;color:${C.tinta}">Uso interno — Confidencial</td></tr>
      </table>
    </div>
  </body></html>`;
}

export async function buildDossier(
  entrada: { preset?: string; desde?: string; hasta?: string },
  opts: { tecnico: boolean }
): Promise<{ buffer: Buffer; filename: string }> {
  let periodo: Periodo;
  try {
    periodo = resolvePeriodo(entrada);
  } catch (e) {
    throw new HttpError(400, e instanceof PeriodoInvalido ? e.message : 'Periodo inválido');
  }
  const cliente = env.REPORT_CLIENT_NAME || 'la organización';
  const hours = Math.min(2160, Math.max(24, periodo.dias * 24));

  const partes = [
    { n: 'I', t: 'Informe Gerencial de Seguridad', d: 'Análisis de dirección: resultados del periodo, gestión de incidentes, postura, plan de acción y hoja de ruta.' },
    { n: 'II', t: 'Informe de Cumplimiento Normativo', d: 'Cobertura frente a Ley 1581, ISO/IEC 27001 y GDPR, y postura de configuración CIS.' },
  ];
  if (opts.tecnico) partes.push({ n: 'III', t: 'Informe Técnico de Operaciones (anexo)', d: 'Detalle operativo con evidencia: reglas, hosts, IPs, CVE, técnicas ATT&CK y consultas reproducibles.' });

  // Componentes (servicios existentes, sin modificarlos)
  const execMetrics = await collectMetrics(periodo);
  const execPdf = await htmlToPdf(buildExecutiveHtml(execMetrics, {}, { organizacion: ORG }));
  const { buffer: compPdf } = await complianceReportPdf(hours);
  let techPdf: Buffer | null = null;
  if (opts.tecnico) {
    const tm = await collectTechMetrics(periodo, 'Informe Técnico de Operaciones de Seguridad');
    techPdf = await htmlToPdf(buildTechnicalHtml(tm));
  }
  const coverPdf = await htmlToPdf(portadaHtml(cliente, periodo, partes), { cssPage: true });

  // Unir con pdfunite
  const dir = mkdtempSync(join(tmpdir(), 'dossier-'));
  try {
    const ordered: Buffer[] = [coverPdf, execPdf, compPdf, ...(techPdf ? [techPdf] : [])];
    const paths = ordered.map((buf, i) => {
      const f = join(dir, `${i}.pdf`);
      writeFileSync(f, buf);
      return f;
    });
    const outPath = join(dir, 'dossier.pdf');
    const r = spawnSync('pdfunite', [...paths, outPath], { timeout: 60_000 });
    if (r.status !== 0 || !existsSync(outPath)) {
      throw new HttpError(500, `No se pudo unir el dosier (${r.error?.message || r.stderr?.toString().slice(0, 120) || 'pdfunite'})`);
    }
    const buffer = readFileSync(outPath);
    const safe = String(cliente).replace(/[^\w.-]+/g, '_').slice(0, 40);
    const filename = `Dosier-Auditoria-${safe}-${periodo.desde}_${periodo.hasta}.pdf`;
    return { buffer, filename };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
