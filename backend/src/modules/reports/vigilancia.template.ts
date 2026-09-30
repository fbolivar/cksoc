/** Render de la sección "Vigilancia extendida" (8 áreas con análisis + evidencia). */
import type { Vigilancia } from './vigilancia.data';

const C = { tinta: '#16323A', marca: '#0B7285', texto: '#33474e', soft: '#5b6b72', linea: '#e2e8ea', zebra: '#f5f9fa', head: '#0A2E36' };

function esc(s: unknown): string {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function gradeTxt(g: string): string {
  return ({ ok: 'OK', warn: 'Revisar', fail: 'Falla', missing: 'Ausente' } as Record<string, string>)[g] || esc(g);
}
function sevColor(s: string): string {
  return ({ critica: '#b91c1c', alta: '#c2410c', media: '#a16207', baja: '#3f6212' } as Record<string, string>)[String(s).toLowerCase()] || C.soft;
}
function h3(n: number, t: string): string {
  return `<h3 style="font-size:12.5pt;color:${C.tinta};margin:16px 0 5px;font-family:'Space Grotesk',sans-serif;font-weight:700">${n}. ${esc(t)}</h3>`;
}
function p(txt: string): string {
  return `<p style="font-size:10pt;line-height:1.55;color:${C.texto};margin:0 0 6px;text-align:justify">${txt}</p>`;
}
function tabla(cols: string[], rows: string[][], anchos?: string[]): string {
  if (!rows.length) return `<p style="font-size:9.5pt;color:${C.soft};margin:2px 0 8px"><i>Sin hallazgos en el periodo.</i></p>`;
  const th = cols.map((c, i) => `<th style="text-align:left;padding:4px 7px;background:${C.head};color:#fff;font-size:8.5pt;${anchos && anchos[i] ? 'width:' + anchos[i] : ''}">${esc(c)}</th>`).join('');
  const tr = rows.map((r, ri) => `<tr style="background:${ri % 2 ? C.zebra : '#fff'}">${r.map((c) => `<td style="padding:4px 7px;border-bottom:1px solid ${C.linea};font-size:9pt;color:${C.tinta};vertical-align:top">${c}</td>`).join('')}</tr>`).join('');
  return `<table style="width:100%;border-collapse:collapse;margin:2px 0 10px;page-break-inside:avoid"><thead><tr>${th}</tr></thead><tbody>${tr}</tbody></table>`;
}
const chip = (t: string, color: string) => `<span style="display:inline-block;padding:0 6px;border-radius:9px;font-size:8pt;font-weight:700;color:#fff;background:${color}">${esc(t)}</span>`;

export function seccionVigilancia(v: Vigilancia | undefined, modo: 'exec' | 'tech' = 'exec'): string {
  if (!v) return '';
  const tech = modo === 'tech';
  const top = <T>(a: T[], nExec: number): T[] => (tech ? a : a.slice(0, nExec));
  const out: string[] = [];

  out.push(`<h2 style="font-size:15pt;color:${C.tinta};margin:26px 0 6px;padding:0 0 6px;border-bottom:2px solid ${C.marca};page-break-after:avoid;font-family:'Space Grotesk',sans-serif;font-weight:700">Vigilancia extendida — análisis y evidencia</h2>`);
  out.push(p('Cobertura del SOC más allá del perímetro y de los endpoints: exposición de credenciales e identidad, actividad en Office&nbsp;365, origen de los ataques, correlación cross-dominio (XDR), superficie expuesta a Internet, suplantación de marca, salud del correo y cumplimiento normativo. Cada bloque incluye el análisis y la evidencia que lo sustenta.'));

  // 1. Credenciales expuestas
  out.push(h3(1, 'Exposición de credenciales'));
  out.push(p(v.cred.total
    ? `Se detectaron <b>${v.cred.total} cuentas corporativas</b> presentes en filtraciones públicas (brechas de terceros). El riesgo es el <b>reuso de contraseñas</b>: si alguna coincide con la del correo/VPN, un atacante entra sin explotar nada. <b>Acción:</b> forzar cambio de contraseña y MFA en las cuentas listadas.`
    : 'No se encontraron credenciales corporativas en filtraciones conocidas durante el periodo.'));
  out.push(tabla(['Cuenta', 'N.º de brechas', 'Aparece en'],
    top(v.cred.items, 3).map((c) => [esc(c.cuenta), String(c.brechas), esc(c.nombres) + (c.brechas > 6 ? '…' : '')]),
    ['34%', '16%', '50%']));

  // 2. Office 365
  out.push(h3(2, 'Office 365 (identidad y correo)'));
  const o = v.o365;
  out.push(p(`En el periodo se registraron <b>${o.logins.toLocaleString('es-CO')} inicios de sesión</b> de ${o.usuarios} usuarios desde ${o.ipsPublicas} direcciones, con <b>${o.fallidos.toLocaleString('es-CO')} intentos fallidos</b> (${o.mfaFail} bloqueados por MFA). ${o.sharingAnon ? `Se detectaron <b>${o.sharingAnon} enlaces de compartición anónima</b> — revisar exposición de archivos.` : 'Sin enlaces de compartición anónima en el periodo.'} La vigilancia de identidad (viaje imposible, MFA-fatiga, accesos fuera de horario) opera de forma continua sobre esta telemetría.`));
  out.push(tabla(['Indicador', 'Valor'], [
    ['Inicios de sesión exitosos', o.logins.toLocaleString('es-CO')],
    ['Usuarios / IPs distintas', `${o.usuarios} / ${o.ipsPublicas}`],
    ['Intentos fallidos', o.fallidos.toLocaleString('es-CO')],
    ['Fallos por MFA (posible ataque)', String(o.mfaFail)],
    ['Compartición anónima', String(o.sharingAnon)],
  ], ['60%', '40%']));

  // 3. Mapa de ataques
  out.push(h3(3, 'Mapa de ataques (origen de las amenazas)'));
  out.push(p(v.ataques.length
    ? `Los ataques contra el perímetro provienen principalmente de los orígenes listados. Todos fueron <b>contenidos por el firewall</b> y los confirmados maliciosos quedan bloqueados automáticamente. Sirve para dimensionar la presión externa y ajustar geobloqueos.`
    : 'No se registraron orígenes de ataque externos relevantes en el periodo.'));
  out.push(tabla(['País', 'Eventos', 'IP (ejemplo)', 'Clasificación'],
    top(v.ataques, 4).map((a) => [esc(a.pais), a.count.toLocaleString('es-CO'), esc(a.ip), esc(a.clasif)]),
    ['30%', '18%', '30%', '22%']));

  // 4. XDR
  out.push(h3(4, 'Correlación cross-dominio (XDR)'));
  out.push(p(v.xdr.total
    ? `El motor XDR agrupó la actividad de alto nivel en <b>${v.xdr.total} conjuntos correlacionados</b> (una misma amenaza vista por firewall, endpoint e identidad se une en un solo caso). Abajo, los de mayor severidad.`
    : 'No se formaron conjuntos correlacionados de alto nivel en la ventana analizada.'));
  out.push(tabla(['Nivel máx.', 'Alertas', 'Reglas', 'Entidades', 'Regla principal'],
    top(v.xdr.items, 3).map((x) => [String(x.maxLevel), String(x.alertas), String(x.reglas), String(x.entidades), esc(x.topRegla).slice(0, tech ? 80 : 45)]),
    ['14%', '13%', '12%', '13%', '48%']));

  // 5. Superficie externa (ASM)
  out.push(h3(5, 'Superficie externa expuesta a Internet (ASM)'));
  out.push(p(v.asm.total
    ? `Se identificaron <b>${v.asm.total} hallazgos</b> de superficie expuesta (${v.asm.criticos} de riesgo alto/crítico): puertos y servicios accesibles, certificados y configuraciones visibles desde Internet. <b>Acción:</b> cerrar/limitar lo que no deba estar público.`
    : 'La superficie externa no presenta hallazgos abiertos en el periodo.'));
  out.push(tabla(['Sev.', 'Objetivo', 'Detalle'],
    top(v.asm.items, 3).map((a) => [chip(a.sev, sevColor(a.sev)), esc(a.objetivo), esc(a.detalle).slice(0, tech ? 90 : 55)]),
    ['12%', '30%', '58%']));

  // 6. Riesgo digital (DRP)
  out.push(h3(6, 'Riesgo digital — suplantación de marca (DRP)'));
  out.push(p(v.drp.total
    ? `Existen <b>${v.drp.total} dominios que imitan la marca</b> (typosquatting); <b>${v.drp.conMx} tienen servidor de correo activo</b>, es decir, capacidad real de enviar correos fraudulentos a nombre de la empresa. <b>Acción:</b> monitorear y gestionar takedown de los de mayor riesgo.`
    : 'No se detectaron dominios que suplanten la marca en el periodo.'));
  out.push(tabla(['Sev.', 'Dominio similar', 'Correo activo', 'Detalle'],
    top(v.drp.items, 4).map((d) => [chip(d.sev, sevColor(d.sev)), esc(d.dominio), d.mx ? chip('MX sí', '#b91c1c') : 'no', esc(d.detalle).slice(0, tech ? 70 : 40)]),
    ['12%', '32%', '16%', '40%']));

  // 7. Postura de correo
  out.push(h3(7, 'Postura de correo (SPF / DKIM / DMARC)'));
  const malas = v.postura.filter((d) => d.grade !== 'ok').length;
  out.push(p(v.postura.length
    ? `Estado de las protecciones anti-suplantación del correo. ${malas ? `<b>${malas} dominio(s) con puntos por endurecer</b> (SPF/DKIM/DMARC): mientras DMARC no esté en <i>reject</i>, un tercero puede falsificar el remitente.` : 'Los dominios evaluados presentan una postura adecuada.'}`
    : 'No hay dominios configurados para evaluación de postura de correo.'));
  out.push(tabla(['Dominio', 'Puntaje', 'SPF', 'DKIM', 'DMARC', 'MX'],
    v.postura.map((d) => [esc(d.domain), `${d.score}/100`, gradeTxt(d.spf), gradeTxt(d.dkim), gradeTxt(d.dmarc), gradeTxt(d.mx)]),
    ['34%', '14%', '13%', '13%', '13%', '13%']));

  // 8. Cumplimiento normativo
  out.push(h3(8, 'Cumplimiento normativo'));
  out.push(p(v.cumplimiento.length
    ? `Cobertura de monitoreo mapeada a los marcos de referencia (cada evento de seguridad se asocia a los controles que vigila). Indica sobre qué controles el SOC ya está generando evidencia continua.`
    : 'Aún no hay actividad mapeada a marcos de cumplimiento en el periodo.'));
  out.push(tabla(['Marco', 'Controles con monitoreo', 'Eventos mapeados'],
    v.cumplimiento.map((f) => [esc(f.marco), String(f.controles), f.total.toLocaleString('es-CO')]),
    ['40%', '32%', '28%']));

  return out.join('\n');
}
