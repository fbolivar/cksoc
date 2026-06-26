/**
 * Traduccion a lenguaje EJECUTIVO + plantilla HTML/PDF del reporte mensual
 * para el Comite SGSI. Alineado a ISO 27001:2022. Identidad PNNC.
 * El valor del modulo esta aqui: lenguaje de gestion, no tecnico.
 */
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import type { ReportMetrics } from './exec.data';

const fmt = (n: number) => n.toLocaleString('es-CO');
const esc = (s: string) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

const SEMAFORO = {
  verde: { color: '#16a34a', label: 'VERDE', texto: 'Operación normal' },
  amarillo: { color: '#eab308', label: 'AMARILLO', texto: 'Incidentes gestionados' },
  rojo: { color: '#ef4444', label: 'ROJO', texto: 'Incidentes críticos por atender' },
};

function logoDataUri(): string | undefined {
  for (const p of [resolve(process.cwd(), '../frontend/public/logo-pnnc.png'), resolve(process.cwd(), 'assets/logo-pnnc.png')]) {
    if (existsSync(p)) return `data:image/png;base64,${readFileSync(p).toString('base64')}`;
  }
  return undefined;
}

/** Resumen ejecutivo por defecto (Fernando puede editarlo). */
export function defaultSummary(m: ReportMetrics): string {
  if (m.semaforo === 'rojo') {
    return `Durante ${m.periodoLabel}, el Centro de Operaciones de Seguridad mantuvo el monitoreo continuo de la infraestructura institucional. Se identificaron ${fmt(m.criticos)} evento(s) de severidad crítica que requieren la atención del Comité y su seguimiento. El resto de la operación se gestionó dentro de los parámetros normales.`;
  }
  if (m.semaforo === 'amarillo') {
    return `Durante ${m.periodoLabel}, el Centro de Operaciones de Seguridad mantuvo monitoreo continuo sobre los servidores críticos de la entidad. Se detectaron y gestionaron intentos de acceso no autorizado dirigidos principalmente a los servicios de acceso remoto (VPN), sin afectación a la operación. Las amenazas fueron registradas, correlacionadas y se cuenta con capacidad de bloqueo. La postura de seguridad del periodo se considera estable bajo gestión activa.`;
  }
  return `Durante ${m.periodoLabel}, la infraestructura tecnológica de Parques Nacionales operó con normalidad. El monitoreo continuo de seguridad no identificó incidentes que comprometieran la operación. Se mantuvieron activas las capacidades de detección, análisis y respuesta del Centro de Operaciones de Seguridad.`;
}

/** Recomendaciones por defecto (editables). */
export function defaultRecommendations(m: ReportMetrics): string {
  const recs = [
    'Mantener el monitoreo continuo y la operación de la plataforma de correlación de eventos (SIEM).',
  ];
  if (m.bruteForceIntentos > 0)
    recs.push('Evaluar el bloqueo proactivo de los orígenes externos recurrentes de fuerza bruta hacia la VPN.');
  recs.push('Avanzar en el endurecimiento de la integración con el directorio activo (migración de NTLM a Kerberos/LDAPS).');
  recs.push('Programar actividades de concientización en seguridad de la información para el personal de la entidad.');
  return recs.map((r) => `• ${r}`).join('\n');
}

// ----------------- secciones HTML -----------------

function h(n: number, t: string): string {
  return `<h2 style="font-size:14px;color:#0f3d24;border-bottom:2px solid #1f7a4d;padding-bottom:4px;margin:22px 0 10px">${n}. ${t}</h2>`;
}
function p(t: string): string {
  return `<p style="font-size:12px;line-height:1.55;margin:0 0 8px;color:#26342e">${t}</p>`;
}

function isoTable(m: ReportMetrics): string {
  const controls: [string, string, string][] = [
    ['A.5.7', 'Inteligencia de amenazas', 'Se consultó reputación de direcciones IP atacantes (AbuseIPDB) para enriquecer el análisis.'],
    ['A.8.15', 'Registro de eventos', `Se registraron y conservaron ${fmt(m.totalEventos)} eventos de seguridad en la plataforma SIEM.`],
    ['A.8.16', 'Actividades de monitoreo', `Monitoreo continuo sobre ${m.agentesActivos}/${m.agentesTotal} servidores de la entidad.`],
    ['A.5.24–A.5.28', 'Gestión de incidentes', `Detección, análisis, respuesta (${m.ipsBloqueadas.length} bloqueo(s)) y evidencia documentada de incidentes.`],
  ];
  const rows = controls.map(([id, name, ev]) =>
    `<tr><td style="padding:6px 8px;border:1px solid #e2e8e4;font-weight:600;white-space:nowrap">${id}</td><td style="padding:6px 8px;border:1px solid #e2e8e4">${esc(name)}</td><td style="padding:6px 8px;border:1px solid #e2e8e4">${esc(ev)}</td></tr>`
  ).join('');
  return `<table style="width:100%;border-collapse:collapse;font-size:11px"><tr style="background:#f0f5f2;color:#0f3d24"><th style="padding:6px 8px;border:1px solid #e2e8e4;text-align:left">Control</th><th style="padding:6px 8px;border:1px solid #e2e8e4;text-align:left">Nombre</th><th style="padding:6px 8px;border:1px solid #e2e8e4;text-align:left">Evidencia del periodo</th></tr>${rows}</table>`;
}

function trendSvg(m: ReportMetrics): string {
  const series = [...m.tendencia, { mes: m.mes, total: m.totalEventos, criticos: m.criticos, bloqueadas: m.ipsBloqueadas.length }];
  if (series.length < 2) {
    return p('Este es el primer reporte ejecutivo del Centro de Operaciones de Seguridad; constituye la <b>línea base</b> contra la cual se compararán los periodos siguientes. A partir del próximo mes se incluirá el análisis de tendencia.');
  }
  const W = 560, H = 140, pad = 30;
  const max = Math.max(...series.map((s) => s.total)) || 1;
  const stepX = (W - pad * 2) / (series.length - 1);
  const pts = series.map((s, i) => {
    const x = pad + i * stepX;
    const y = H - pad - (s.total / max) * (H - pad * 2);
    return [x, y] as const;
  });
  const line = pts.map((pt, i) => `${i === 0 ? 'M' : 'L'} ${pt[0].toFixed(0)} ${pt[1].toFixed(0)}`).join(' ');
  const labels = series.map((s, i) => `<text x="${pad + i * stepX}" y="${H - 8}" font-size="9" fill="#6b7c74" text-anchor="middle">${s.mes}</text>`).join('');
  return `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}"><path d="${line}" fill="none" stroke="#1f7a4d" stroke-width="2"/>${pts.map((pt) => `<circle cx="${pt[0]}" cy="${pt[1]}" r="3" fill="#1f7a4d"/>`).join('')}${labels}<text x="${pad}" y="14" font-size="9" fill="#6b7c74">Eventos por mes (pico ${fmt(max)})</text></svg>`;
}

/**
 * Genera el HTML del reporte ejecutivo. resumen/recomendaciones pueden venir
 * editados por Fernando; si no, se usan los textos por defecto.
 */
export function buildExecutiveHtml(
  m: ReportMetrics,
  overrides: { resumen?: string | null; recomendaciones?: string | null }
): string {
  const sem = SEMAFORO[m.semaforo];
  const logo = logoDataUri();
  const resumen = overrides.resumen || defaultSummary(m);
  const recomendaciones = overrides.recomendaciones || defaultRecommendations(m);
  const fechaGen = new Date(m.generadoEn).toLocaleDateString('es-CO', { dateStyle: 'long' });

  // 3. Incidentes
  let incidentes = '';
  if (m.bruteForceIntentos > 0) {
    incidentes += p(`<b>Intentos de acceso no autorizado (VPN).</b> Se registraron ${fmt(m.bruteForceIntentos)} intentos de fuerza bruta contra el servicio de acceso remoto, provenientes de ${fmt(m.bruteForceOrigenes)} direcciones externas distintas. <b>Severidad:</b> Alta. <b>Estado:</b> Detectado y bajo monitoreo; orígenes disponibles para bloqueo. <b>Acción:</b> registro, correlación automática y notificación al equipo.`);
  }
  if (m.criticos > 0) {
    incidentes += p(`<b>Eventos de severidad crítica.</b> Se identificaron ${fmt(m.criticos)} evento(s) crítico(s) que requieren revisión y seguimiento por parte del área.`);
  }
  if (!incidentes) incidentes = p('No se registraron incidentes significativos durante el periodo. La actividad correspondió a la operación normal de la infraestructura.');

  // 4. Panorama
  const origenesTxt = m.origenes.length
    ? `Los intentos de actividad sospechosa con origen externo se concentraron en: ${m.origenes.map((o) => `${esc(o.country)} (${o.count})`).join(', ')}.`
    : 'No se identificaron orígenes externos de actividad sospechosa con dirección pública en el periodo.';

  // 5. Acciones
  const accionesIps = m.ipsBloqueadas.length
    ? `Se bloquearon ${m.ipsBloqueadas.length} dirección(es) IP en el firewall perimetral como respuesta a actividad maliciosa, con registro de auditoría (responsable, motivo y fecha).`
    : 'Durante el periodo no fue necesario aplicar bloqueos en el firewall; la actividad detectada se mantuvo bajo monitoreo.';

  const content = `
    ${h(1, 'Resumen Ejecutivo')}
    <div style="display:flex;align-items:center;gap:14px;margin:0 0 12px;padding:12px 16px;background:#f7faf8;border-left:5px solid ${sem.color};border-radius:6px">
      <div style="width:18px;height:18px;border-radius:50%;background:${sem.color}"></div>
      <div><b style="color:${sem.color}">Postura ${sem.label}</b> &middot; <span style="color:#26342e">${sem.texto}</span></div>
    </div>
    ${p(esc(resumen).replace(/\n/g, '<br>'))}
    <p style="font-size:11px;color:#6b7c74">Periodo: ${m.rangoTexto} &middot; Generado: ${fechaGen}</p>

    ${h(2, 'Postura de Seguridad')}
    ${p(`Se mantiene monitoreo continuo de seguridad sobre los servidores críticos de la entidad. Cobertura actual: <b>${m.agentesActivos} de ${m.agentesTotal}</b> servidores monitoreados, con disponibilidad del monitoreo cercana al 100%.`)}
    ${p('Capacidades activas del Centro de Operaciones de Seguridad: <b>detección</b> de eventos en tiempo real, <b>geolocalización</b> de orígenes de ataque, <b>inteligencia de amenazas</b> (reputación de IPs) y <b>respuesta</b> con bloqueo bajo confirmación.')}

    ${h(3, 'Incidentes del Mes')}
    ${incidentes}

    ${h(4, 'Panorama de Amenazas')}
    ${p(origenesTxt)}
    ${p('El tipo de amenaza predominante corresponde a <b>intentos de fuerza bruta</b> contra el acceso remoto (VPN), un patrón habitual de exposición en servicios publicados a Internet. Se distingue la actividad maliciosa externa de la operación normal de los usuarios internos de la entidad.')}

    ${h(5, 'Acciones y Mitigaciones')}
    ${p(accionesIps)}
    ${p('Se optimizaron las reglas de detección para reducir falsos positivos y mejorar la precisión del monitoreo, enfocando la atención del equipo en los eventos realmente relevantes.')}
    ${m.ipsBloqueadas.length ? `<p style="font-size:10px;color:#6b7c74">Direcciones bloqueadas: ${m.ipsBloqueadas.slice(0, 10).map((b) => esc(b.ip)).join(', ')}${m.ipsBloqueadas.length > 10 ? '…' : ''}</p>` : ''}

    ${h(6, 'Cumplimiento ISO/IEC 27001:2022')}
    ${p('La operación del Centro de Operaciones de Seguridad durante el periodo evidencia los siguientes controles del Anexo A:')}
    ${isoTable(m)}

    ${h(7, 'Tendencias')}
    ${trendSvg(m)}

    ${h(8, 'Recomendaciones')}
    ${p(esc(recomendaciones).replace(/\n/g, '<br>'))}
  `;

  return `<!doctype html><html lang="es"><head><meta charset="utf-8"><style>
    @page { margin: 0; }
    * { box-sizing: border-box; }
    body { font-family: 'Liberation Sans', Arial, sans-serif; margin: 0; color: #1f2a26; }
    .cover { height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center; background: linear-gradient(160deg,#0f3d24,#0a5c34); color: #fff; page-break-after: always; }
    .cover img { height: 70px; background: #fff; padding: 6px; border-radius: 8px; margin-bottom: 24px; }
    .content { padding: 28px 34px 60px; }
    .footer-band { position: fixed; bottom: 0; left: 0; right: 0; background: #0f3d24; color: #cfe6da; font-size: 9px; padding: 5px 34px; display: flex; justify-content: space-between; }
  </style></head><body>
    <div class="cover">
      ${logo ? `<img src="${logo}" alt="PNNC">` : ''}
      <div style="font-size:13px;letter-spacing:3px;color:#9fe9c5">PARQUES NACIONALES NATURALES DE COLOMBIA</div>
      <h1 style="font-size:26px;margin:14px 0 6px">Reporte Ejecutivo de Seguridad</h1>
      <div style="font-size:16px;color:#cfe6da">${m.periodoLabel}</div>
      <div style="margin-top:30px;font-size:12px;color:#9fb3aa">Centro de Operaciones de Seguridad &middot; Comité de Seguridad / SGSI</div>
      <div style="margin-top:6px;font-size:11px;color:#7f9488">Documento alineado a ISO/IEC 27001:2022</div>
    </div>
    <div class="content">${content}</div>
    <div class="footer-band"><span>SOC PNNC &middot; Reporte Ejecutivo ${m.periodoLabel}</span><span>Clasificación: USO INTERNO — Comité de Seguridad</span></div>
  </body></html>`;
}

/** Cuerpo de correo (resumen + semaforo; el PDF va adjunto). */
export function executiveEmailHtml(m: ReportMetrics, resumen: string): string {
  const sem = SEMAFORO[m.semaforo];
  return `<div style="font-family:Inter,Arial,sans-serif;max-width:620px;margin:auto;background:#0f1613;color:#e6f2ec;border-radius:12px;overflow:hidden;border:1px solid #1d2b25">
    <div style="background:#0f3d24;padding:16px 24px;border-bottom:3px solid #85b425"><h2 style="margin:0;font-size:15px;color:#fff">Reporte Ejecutivo de Seguridad &middot; ${m.periodoLabel}</h2><p style="margin:2px 0 0;font-size:11px;color:#cfe6da">Parques Nacionales Naturales de Colombia &middot; Comité de Seguridad / SGSI</p></div>
    <div style="padding:22px 24px">
      <div style="display:inline-flex;align-items:center;gap:8px;padding:6px 12px;border-radius:6px;background:${sem.color}22;border:1px solid ${sem.color}55;margin-bottom:14px"><span style="width:12px;height:12px;border-radius:50%;background:${sem.color}"></span><b style="color:${sem.color}">Postura ${sem.label}</b> <span style="color:#9fb3aa">— ${sem.texto}</span></div>
      <p style="font-size:13px;line-height:1.6">${esc(resumen).replace(/\n/g, '<br>')}</p>
      <p style="font-size:12px;color:#9fb3aa;margin-top:16px">Se adjunta el reporte ejecutivo completo (8 secciones, alineado a ISO 27001) en formato PDF para el acta del Comité.</p>
    </div>
    <div style="padding:12px 24px;border-top:1px solid #1d2b25;color:#6b7c74;font-size:10px;display:flex;justify-content:space-between"><span>Periodo: ${m.rangoTexto}</span><span>Confidencial &middot; Uso interno</span></div>
  </div>`;
}
