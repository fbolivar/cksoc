/**
 * Plantilla HTML/PDF del INFORME GERENCIAL DE SEGURIDAD DE LA INFORMACION.
 *
 * Estructura del documento:
 *   Portada · Ficha e indice
 *   1. Introduccion
 *   2. Objetivos del informe
 *   3. Alcance y cobertura
 *   4. Resultados del periodo
 *   5. Analisis
 *   6. Conclusiones
 *   7. Recomendaciones
 *   8. Plan de accion
 *   9. Hoja de ruta
 *   10. Anexos (glosario, metodologia, marco normativo)
 *
 * Audiencia: Direccion / Gerencia. Lenguaje NO tecnico.
 */
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import type { ReportMetrics } from './exec.data';
import { analizar, ETIQUETA_CRITICIDAD, duracionTexto, type Analisis, type AccionPlan, type FaseRuta, type Criticidad } from './exec.analysis';
import { fechaLarga, etiquetaBucket } from './periodo';

// --------------------------------------------------------------------------
// Overrides editables por el responsable del informe
// --------------------------------------------------------------------------

export interface SeccionesEditables {
  resumen?: string | null;
  introduccion?: string | null;
  objetivos?: string | null;
  alcance?: string | null;
  resultados?: string | null;
  analisis?: string | null;
  conclusiones?: string | null;
  recomendaciones?: string | null;
  planAccion?: string | null;
  hojaRuta?: string | null;
  novedades?: string | null;
}

// --------------------------------------------------------------------------
// Utilidades
// --------------------------------------------------------------------------

const fmt = (n: number): string => n.toLocaleString('es-CO');
const esc = (s: unknown): string =>
  String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

const C = {
  tinta: '#16181d',
  texto: '#31363f',
  suave: '#6b7280',
  linea: '#e4e7ec',
  fondo: '#f7f8fa',
  marca: '#f0512e',
  marcaOsc: '#b8371a',
  crit: '#b91c1c',
  alta: '#c2410c',
  media: '#b45309',
  baja: '#0f766e',
  ok: '#15803d',
};

const COLOR_CRIT: Record<Criticidad, string> = {
  critica: C.crit, alta: C.alta, media: C.media, baja: C.baja,
};

const SEMAFORO = {
  verde: { color: C.ok, label: 'FAVORABLE', texto: 'Operación normal, sin situaciones que comprometan el servicio' },
  amarillo: { color: '#d97706', label: 'ESTABLE BAJO GESTIÓN', texto: 'Riesgos identificados y controlados, con acciones en curso' },
  rojo: { color: C.crit, label: 'REQUIERE ATENCIÓN', texto: 'Existen condiciones de riesgo que exigen decisión de la Dirección' },
};

function logoDataUri(): string | undefined {
  for (const p of [
    resolve(process.cwd(), '../frontend/public/logo-pnnc.png'),
    resolve(process.cwd(), 'assets/logo-pnnc.png'),
  ]) {
    if (existsSync(p)) return `data:image/png;base64,${readFileSync(p).toString('base64')}`;
  }
  return undefined;
}

/**
 * Texto enriquecido simple: parrafos separados por linea en blanco, listas con
 * "-", "•" o "1.", y negrilla con **texto**. Todo se escapa antes.
 */
function rich(t: string, size = 11.5): string {
  const bloques = String(t ?? '').split(/\n\s*\n/);
  const negrilla = (s: string): string => s.replace(/\*\*(.+?)\*\*/g, '<b>$1</b>');
  return bloques
    .map((bl) => {
      const lineas = bl.split('\n').map((l) => l.trim()).filter(Boolean);
      if (lineas.length === 0) return '';
      const esLista = lineas.every((l) => /^([-•*]|\d+[.)])\s+/.test(l));
      if (esLista) {
        const items = lineas
          .map((l) => `<li style="margin:0 0 5px">${negrilla(esc(l.replace(/^([-•*]|\d+[.)])\s+/, '')))}</li>`)
          .join('');
        return `<ul style="font-size:${size}px;line-height:1.6;color:${C.texto};margin:0 0 10px;padding-left:18px">${items}</ul>`;
      }
      return `<p style="font-size:${size}px;line-height:1.65;color:${C.texto};margin:0 0 9px;text-align:justify">${negrilla(esc(bl.replace(/\n/g, ' ')))}</p>`;
    })
    .join('');
}

/** Lista a partir de un array de strings. */
function lista(items: string[], size = 11.5): string {
  if (items.length === 0) return '';
  return `<ul style="font-size:${size}px;line-height:1.6;color:${C.texto};margin:0 0 10px;padding-left:18px">${items
    .map((i) => `<li style="margin:0 0 6px">${esc(i)}</li>`)
    .join('')}</ul>`;
}

function h2(n: number, t: string): string {
  return `<h2 style="font-size:15px;color:${C.tinta};margin:26px 0 12px;padding:0 0 6px;border-bottom:2px solid ${C.marca};page-break-after:avoid">
    <span style="display:inline-block;min-width:22px;color:${C.marca}">${n}.</span>${esc(t)}</h2>`;
}

function h3(t: string): string {
  return `<h3 style="font-size:12px;color:${C.tinta};margin:16px 0 7px;page-break-after:avoid">${esc(t)}</h3>`;
}

function nota(t: string): string {
  return `<p style="font-size:9.5px;color:${C.suave};margin:4px 0 12px;font-style:italic">${esc(t)}</p>`;
}

// --------------------------------------------------------------------------
// Componentes visuales
// --------------------------------------------------------------------------

interface Kpi { valor: string; etiqueta: string; pie?: string; color?: string }

function kpiGrid(kpis: Kpi[]): string {
  // Se maqueta con tabla: es lo unico que pagina de forma predecible en PDF.
  const porFila = 4;
  const celdas = kpis.map(
    (k) => `<td style="width:${Math.floor(100 / porFila)}%;padding:4px;vertical-align:top">
      <div style="border:1px solid ${C.linea};border-left:3px solid ${k.color ?? C.marca};background:#fff;padding:10px 12px;border-radius:4px">
        <div style="font-size:19px;font-weight:700;color:${k.color ?? C.tinta};line-height:1.15">${esc(k.valor)}</div>
        <div style="font-size:9px;color:${C.texto};margin-top:3px;font-weight:700;text-transform:uppercase;letter-spacing:.3px">${esc(k.etiqueta)}</div>
        ${k.pie ? `<div style="font-size:8.5px;color:${C.suave};margin-top:2px;line-height:1.35">${esc(k.pie)}</div>` : ''}
      </div></td>`
  );
  const filas: string[] = [];
  for (let i = 0; i < celdas.length; i += porFila) {
    const grupo = celdas.slice(i, i + porFila);
    while (grupo.length < porFila) grupo.push('<td style="padding:4px"></td>');
    filas.push(`<tr>${grupo.join('')}</tr>`);
  }
  return `<table style="width:100%;border-collapse:collapse;margin:6px 0 14px;page-break-inside:avoid">${filas.join('')}</table>`;
}

function tabla(
  cols: string[],
  filas: string[][],
  opts: { anchos?: string[]; size?: number } = {}
): string {
  const size = opts.size ?? 10;
  const th = cols
    .map(
      (c, i) =>
        `<th style="padding:7px 9px;border-bottom:2px solid ${C.tinta};text-align:left;font-size:${size}px;color:${C.tinta};${opts.anchos?.[i] ? `width:${opts.anchos[i]};` : ''}">${esc(c)}</th>`
    )
    .join('');
  const tb = filas
    .map(
      (f, ri) =>
        `<tr style="background:${ri % 2 ? C.fondo : '#fff'}">${f
          .map((v) => `<td style="padding:6px 9px;border-bottom:1px solid ${C.linea};font-size:${size}px;color:${C.texto};vertical-align:top">${v}</td>`)
          .join('')}</tr>`
    )
    .join('');
  return `<table style="width:100%;border-collapse:collapse;margin:6px 0 14px;page-break-inside:avoid"><thead><tr>${th}</tr></thead><tbody>${tb}</tbody></table>`;
}

function pill(texto: string, color: string): string {
  return `<span style="display:inline-block;padding:1px 7px;border-radius:9px;background:${color}1a;color:${color};font-size:9px;font-weight:700;white-space:nowrap">${esc(texto)}</span>`;
}

function flecha(pct: number | null): string {
  if (pct === null) return `<span style="color:${C.suave}">sin comparación</span>`;
  if (Math.abs(pct) < 5) return `<span style="color:${C.suave}">= estable (${pct >= 0 ? '+' : ''}${pct} %)</span>`;
  const sube = pct > 0;
  return `<span style="color:${sube ? C.alta : C.ok};font-weight:600">${sube ? '▲' : '▼'} ${Math.abs(pct)} %</span>`;
}

/** Grafico de barras de la serie temporal del periodo. */
function graficoSerie(m: ReportMetrics): string {
  const s = m.serie.filter((x) => x.total > 0 || m.serie.length <= 40);
  if (s.length < 2) return nota('No hay suficientes datos en el periodo para representar la evolución diaria.');
  const W = 640, H = 170, padL = 40, padR = 12, padT = 16, padB = 26;
  const max = Math.max(...s.map((x) => x.total), 1);
  const bw = (W - padL - padR) / s.length;
  const barras = s
    .map((x, i) => {
      const hgt = ((H - padT - padB) * x.total) / max;
      const y = H - padB - hgt;
      const xc = padL + i * bw;
      const crit = x.criticos > 0 ? ((H - padT - padB) * x.criticos) / max : 0;
      return `<rect x="${(xc + bw * 0.15).toFixed(1)}" y="${y.toFixed(1)}" width="${(bw * 0.7).toFixed(1)}" height="${Math.max(hgt, 0.6).toFixed(1)}" fill="${C.marca}" opacity="0.75"/>` +
        (crit > 0 ? `<rect x="${(xc + bw * 0.15).toFixed(1)}" y="${(H - padB - crit).toFixed(1)}" width="${(bw * 0.7).toFixed(1)}" height="${Math.max(crit, 1.2).toFixed(1)}" fill="${C.crit}"/>` : '');
    })
    .join('');
  const paso = Math.max(1, Math.ceil(s.length / 12));
  const ejeX = s
    .map((x, i) => (i % paso === 0
      ? `<text x="${(padL + i * bw + bw / 2).toFixed(1)}" y="${H - 9}" font-size="8" fill="${C.suave}" text-anchor="middle">${esc(etiquetaBucket(x.ts, m.periodo.granularidad))}</text>`
      : ''))
    .join('');
  const ejeY = [0, 0.5, 1]
    .map((f) => {
      const y = H - padB - (H - padT - padB) * f;
      return `<line x1="${padL}" y1="${y}" x2="${W - padR}" y2="${y}" stroke="${C.linea}"/><text x="${padL - 5}" y="${y + 3}" font-size="8" fill="${C.suave}" text-anchor="end">${fmt(Math.round(max * f))}</text>`;
    })
    .join('');
  return `<div style="page-break-inside:avoid"><svg width="100%" viewBox="0 0 ${W} ${H}" style="max-width:100%">${ejeY}${barras}${ejeX}</svg>
    <div style="font-size:9px;color:${C.suave};margin-top:2px">
      <span style="display:inline-block;width:9px;height:9px;background:${C.marca};opacity:.75;vertical-align:-1px"></span> Actividad analizada &nbsp;
      <span style="display:inline-block;width:9px;height:9px;background:${C.crit};vertical-align:-1px"></span> Eventos de máxima severidad
    </div></div>`;
}

/** Comparativo del periodo actual contra el anterior. */
function graficoComparativo(m: ReportMetrics): string {
  if (!m.anterior) return '';
  if (m.anterior.totalEventos === 0 && m.anterior.incidentes === 0) {
    return nota(`El intervalo equivalente anterior (${m.anterior.rangoTexto}) no registra información en la plataforma de vigilancia. Este periodo constituye la línea base de medición y la comparación estará disponible en el siguiente informe.`);
  }
  const filas: [string, number, number][] = [
    ['Actividad analizada', m.anterior.totalEventos, m.totalEventos],
    ['Severidad máxima', m.anterior.criticos, m.criticos],
    ['Severidad alta', m.anterior.altos, m.altos],
    ['Bloqueos aplicados', m.anterior.ipsBloqueadas, m.ipsBloqueadas.length],
    ['Casos gestionados', m.anterior.incidentes, m.gestion.total],
  ];
  return tabla(
    ['Indicador', `Periodo anterior<br><span style="font-weight:400;color:${C.suave};font-size:9px">${esc(m.anterior.rangoTexto)}</span>`, `Periodo actual<br><span style="font-weight:400;color:${C.suave};font-size:9px">${esc(m.rangoTexto)}</span>`, 'Variación'],
    filas.map(([n, a, b]) => [
      `<b>${esc(n)}</b>`,
      fmt(a),
      `<b>${fmt(b)}</b>`,
      flecha(a === 0 ? (b === 0 ? 0 : null) : Math.round(((b - a) / a) * 100)),
    ]),
    { anchos: ['34%', '22%', '22%', '22%'] }
  );
}

/** Tendencia historica de meses previos (si hay snapshots). */
function graficoTendencia(m: ReportMetrics): string {
  const serie = [...m.tendencia, { mes: m.mes, total: m.totalEventos, criticos: m.criticos, bloqueadas: m.ipsBloqueadas.length }];
  if (serie.length < 3) return '';
  const W = 620, H = 130, pad = 34;
  const max = Math.max(...serie.map((s) => s.total), 1);
  const stepX = (W - pad * 2) / (serie.length - 1);
  const pts = serie.map((s, i) => [pad + i * stepX, H - pad - (s.total / max) * (H - pad * 1.6)] as const);
  const line = pts.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p[0].toFixed(0)} ${p[1].toFixed(0)}`).join(' ');
  const area = `${line} L ${pts[pts.length - 1][0].toFixed(0)} ${H - pad} L ${pts[0][0].toFixed(0)} ${H - pad} Z`;
  const labels = serie
    .map((s, i) => `<text x="${(pad + i * stepX).toFixed(0)}" y="${H - 10}" font-size="8" fill="${C.suave}" text-anchor="middle">${esc(s.mes)}</text>`)
    .join('');
  return `${h3('Evolución de los últimos meses')}<div style="page-break-inside:avoid"><svg width="100%" viewBox="0 0 ${W} ${H}" style="max-width:100%">
    <path d="${area}" fill="${C.marca}" opacity="0.10"/>
    <path d="${line}" fill="none" stroke="${C.marca}" stroke-width="2"/>
    ${pts.map((p) => `<circle cx="${p[0].toFixed(0)}" cy="${p[1].toFixed(0)}" r="3" fill="${C.marca}"/>`).join('')}
    ${labels}<text x="${pad}" y="13" font-size="8" fill="${C.suave}">Actividad analizada por mes (máximo ${fmt(max)})</text>
  </svg></div>`;
}

// --------------------------------------------------------------------------
// Parseo de overrides estructurados (plan de accion)
// --------------------------------------------------------------------------

/** Formato de una linea: accion | prioridad | responsable | plazo | indicador */
export function parsePlanAccion(texto: string): AccionPlan[] {
  return texto
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && l.includes('|'))
    .map((l, i) => {
      const [accion = '', prioridad = 'media', responsable = '', plazo = '', indicador = ''] = l.split('|').map((x) => x.trim());
      const pr = prioridad.toLowerCase();
      const p: Criticidad = pr.startsWith('crit') ? 'critica' : pr.startsWith('alt') ? 'alta' : pr.startsWith('baj') ? 'baja' : 'media';
      return { n: i + 1, accion, prioridad: p, responsable, plazo, indicador, origen: '' };
    });
}

/** Serializa el plan al formato editable. */
export function planAccionATexto(plan: AccionPlan[]): string {
  return plan
    .map((a) => `${a.accion} | ${ETIQUETA_CRITICIDAD[a.prioridad]} | ${a.responsable} | ${a.plazo} | ${a.indicador}`)
    .join('\n');
}

// --------------------------------------------------------------------------
// Secciones
// --------------------------------------------------------------------------

function seccionResultados(m: ReportMetrics, a: Analisis, ov: SeccionesEditables): string {
  const kpis: Kpi[] = [
    { valor: fmt(m.totalEventos), etiqueta: 'Actividad analizada', pie: 'registros procesados automáticamente' },
    { valor: fmt(m.criticos), etiqueta: 'Severidad máxima', pie: 'eventos que exigieron revisión', color: m.criticos > 0 ? C.crit : C.ok },
    { valor: fmt(m.altos), etiqueta: 'Severidad alta', pie: 'eventos relevantes', color: m.altos > 0 ? C.alta : C.ok },
    { valor: `${m.coberturaPct} %`, etiqueta: 'Cobertura de vigilancia', pie: `${fmt(m.agentesActivos)} de ${fmt(m.agentesTotal)} equipos`, color: m.coberturaPct >= 95 ? C.ok : C.alta },
    { valor: fmt(m.gestion.total), etiqueta: 'Casos gestionados', pie: `${fmt(m.gestion.resueltos)} resueltos en el periodo` },
    { valor: duracionTexto(m.gestion.mttaMinutos), etiqueta: 'Tiempo de reacción', pie: 'promedio hasta la primera atención' },
    { valor: fmt(m.ipsBloqueadas.length), etiqueta: 'Bloqueos aplicados', pie: 'orígenes contenidos en el perímetro' },
    { valor: fmt(m.postura?.vulnCriticas ?? 0), etiqueta: 'Fallas críticas', pie: 'pendientes de actualización', color: (m.postura?.vulnCriticas ?? 0) > 0 ? C.crit : C.ok },
  ];

  let out = kpiGrid(kpis);
  out += rich(ov.resultados || a.resultados);

  // Comparativo
  if (m.anterior) {
    out += h3('Comparación con el periodo anterior');
    out += graficoComparativo(m);
  }

  // Evolucion
  out += h3('Evolución de la actividad durante el periodo');
  out += graficoSerie(m);

  // Actividad por semana (equipos mas activos de cada semana)
  if (m.actividadSemanal.length >= 2) {
    out += h3('Actividad por semana');
    out += tabla(
      ['Semana', 'Eventos', 'Equipo más activo', 'Día de mayor actividad'],
      m.actividadSemanal.map((s) => [
        `<b>${esc(s.etiqueta)}</b>`,
        fmt(s.total),
        esc(s.equipoTop ?? '—'),
        esc(s.diaPico ?? '—'),
      ]),
      { anchos: ['34%', '18%', '28%', '20%'] }
    );
    out += nota('El equipo con más actividad no es el de mayor riesgo: normalmente es el que presta más servicios o soporta más usuarios. Esta vista permite seguir semana a semana qué equipos concentran la operación.');
  }

  // Gestion de casos
  if (m.gestion.total > 0) {
    out += h3('Atención de casos');
    out += tabla(
      ['Indicador de gestión', 'Resultado del periodo', 'Lectura'],
      [
        ['Casos abiertos', fmt(m.gestion.total), 'Situaciones que requirieron intervención formal del equipo.'],
        ['Casos resueltos', `${fmt(m.gestion.resueltos)} (${m.gestion.tasaResolucion ?? 0} %)`, 'Cerrados dentro del periodo con solución verificada.'],
        ['Tiempo hasta la primera atención', duracionTexto(m.gestion.mttaMinutos), 'Cuánto tarda la organización en empezar a reaccionar.'],
        ['Tiempo hasta la solución', duracionTexto(m.gestion.mttrMinutos), 'Cuánto tarda en quedar completamente resuelto.'],
        ['Cumplimiento de tiempos comprometidos', m.gestion.cumplimientoSlaPct !== null ? `${m.gestion.cumplimientoSlaPct} %` : 'sin dato', 'Proporción atendida dentro del plazo acordado por severidad.'],
        ['Casos aún abiertos', fmt(m.gestion.abiertos), m.gestion.masAntiguoAbiertoDias !== null ? `El más antiguo lleva ${m.gestion.masAntiguoAbiertoDias} día(s).` : 'Sin casos pendientes.'],
      ],
      { anchos: ['34%', '22%', '44%'] }
    );
    out += tabla(
      ['Severidad del caso', 'Cantidad'],
      (['critica', 'alta', 'media', 'baja'] as const).map((s) => [
        `${pill(ETIQUETA_CRITICIDAD[s], COLOR_CRIT[s])}`,
        fmt(m.gestion.porSeveridad[s] ?? 0),
      ]),
      { anchos: ['60%', '40%'] }
    );
  }

  // Amenazas y equipos
  if (m.topAmenazas.length > 0) {
    out += h3('Situaciones más frecuentes detectadas');
    out += tabla(
      ['Situación detectada', 'Veces registrada'],
      m.topAmenazas.slice(0, 8).map((t) => [esc(t.tipo), fmt(t.conteo)]),
      { anchos: ['74%', '26%'] }
    );
    out += nota('El nombre de cada situación proviene de la regla de detección que la identificó; se conserva como evidencia técnica trazable.');
  }
  if (m.equiposMasAfectados.length > 0) {
    out += h3('Equipos con mayor actividad registrada');
    out += tabla(
      ['Equipo', 'Registros de actividad'],
      m.equiposMasAfectados.slice(0, 6).map((t) => [esc(t.equipo), fmt(t.conteo)]),
      { anchos: ['74%', '26%'] }
    );
    out += nota('Un mayor número de registros no implica que el equipo esté comprometido: normalmente refleja que presta más servicios o soporta más usuarios.');
  }

  // Origenes
  if (m.origenes.length > 0) {
    out += h3('Origen geográfico de la actividad sospechosa');
    out += tabla(
      ['País de origen', 'Direcciones de Internet observadas'],
      m.origenes.map((o) => [esc(o.country), fmt(o.count)]),
      { anchos: ['70%', '30%'] }
    );
  }

  // Postura
  const ps = m.postura;
  if (ps) {
    out += h3('Estado de actualización y configuración de los equipos');
    const filas: string[][] = [
      ['Debilidades de software conocidas', `${ps.vulnTotalAprox ? '≥ ' : ''}${fmt(ps.vulnTotal)}`, `Fallas ya publicadas por los fabricantes, con corrección generalmente disponible.${ps.vulnTotalAprox ? ' El conteo exacto supera el límite de la consulta; la cifra es un mínimo.' : ''}`],
      ['De nivel crítico', `<b style="color:${C.crit}">${fmt(ps.vulnCriticas)}</b>`, 'Deben corregirse con prioridad sobre cualquier otro mantenimiento.'],
      ['De nivel alto', `<b style="color:${C.alta}">${fmt(ps.vulnAltas)}</b>`, 'Deben incluirse en el siguiente ciclo de actualizaciones.'],
      ['Con explotación activa confirmada', `<b style="color:${C.crit}">${fmt(ps.vulnKev)}</b>`, 'Los atacantes ya las están usando en ataques reales en el mundo.'],
      ['Nivel de configuración segura', `${ps.hardeningScore} %`, 'Cumplimiento frente al estándar internacional de configuración (CIS).'],
    ];
    out += tabla(['Aspecto evaluado', 'Resultado', 'Qué significa'], filas, { anchos: ['32%', '16%', '52%'] });
    if (ps.topCves.length) {
      out += nota(`Identificadores técnicos de las fallas prioritarias (para el equipo de TI): ${ps.topCves.map((c) => `${c.cve}${c.inKev ? ' (explotación activa)' : ''}`).join(', ')}.`);
    }
  }

  return out;
}

function seccionAnalisis(m: ReportMetrics, a: Analisis, ov: SeccionesEditables): string {
  let out = rich(ov.analisis || a.analisis);
  out += graficoTendencia(m);

  // Hallazgos priorizados
  if (a.hallazgos.length) {
    out += h3('Situaciones identificadas, ordenadas por prioridad');
    out += tabla(
      ['#', 'Prioridad', 'Situación', 'Qué se observó', 'Qué implica para la organización'],
      a.hallazgos.map((hg, i) => [
        String(i + 1),
        pill(ETIQUETA_CRITICIDAD[hg.criticidad], COLOR_CRIT[hg.criticidad]),
        `<b>${esc(hg.titulo)}</b>`,
        esc(hg.observacion),
        esc(hg.impacto),
      ]),
      { anchos: ['4%', '10%', '20%', '33%', '33%'], size: 9.5 }
    );
  }

  // Fortalezas
  if (a.fortalezas.length) {
    out += h3('Fortalezas del periodo');
    out += `<table style="width:100%;border-collapse:collapse;margin:4px 0 12px;page-break-inside:avoid">${a.fortalezas
      .map(
        (f) => `<tr><td style="padding:6px 9px;border-left:3px solid ${C.ok};background:${C.fondo}">
          <b style="font-size:10.5px;color:${C.tinta}">${esc(f.titulo)}.</b>
          <span style="font-size:10.5px;color:${C.texto}"> ${esc(f.detalle)}</span></td></tr>
          <tr><td style="height:5px"></td></tr>`
      )
      .join('')}</table>`;
  }

  return out;
}

function seccionPlanAccion(a: Analisis, ov: SeccionesEditables): string {
  const plan: AccionPlan[] = ov.planAccion ? parsePlanAccion(ov.planAccion) : a.planAccion;
  if (plan.length === 0) return rich('No se registran acciones pendientes para el periodo.');
  let out = rich(
    'El siguiente plan traduce cada situación identificada en una acción concreta, con un responsable, una fecha objetivo y un indicador que permite verificar su cumplimiento en el próximo informe. Las fechas objetivo se calculan desde la fecha de emisión de este documento y son ajustables por la Dirección según la disponibilidad de recursos.'
  );
  out += tabla(
    ['#', 'Acción a ejecutar', 'Prioridad', 'Responsable', 'Fecha objetivo', 'Cómo se verifica'],
    plan.map((p) => [
      String(p.n),
      `<b>${esc(p.accion)}</b>`,
      pill(ETIQUETA_CRITICIDAD[p.prioridad], COLOR_CRIT[p.prioridad]),
      esc(p.responsable),
      esc(p.plazo),
      esc(p.indicador),
    ]),
    { anchos: ['4%', '30%', '9%', '16%', '15%', '26%'], size: 9.5 }
  );
  return out;
}

function seccionHojaRuta(a: Analisis, ov: SeccionesEditables): string {
  if (ov.hojaRuta) return rich(ov.hojaRuta);
  const fases: FaseRuta[] = a.hojaRuta;
  if (fases.length === 0) return rich('No se proponen iniciativas adicionales para los próximos meses.');
  let out = rich(
    'La hoja de ruta organiza las acciones en fases sucesivas. El objetivo no es ejecutarlo todo de inmediato, sino avanzar de forma ordenada: primero cerrar la exposición más urgente, luego eliminar sus causas y, finalmente, consolidar la seguridad como una capacidad permanente y medible de la organización.'
  );
  out += fases
    .map(
      (f, i) => `<div style="page-break-inside:avoid;margin:0 0 10px;border:1px solid ${C.linea};border-radius:5px;overflow:hidden">
      <div style="background:${C.tinta};color:#fff;padding:7px 12px;display:flex;justify-content:space-between">
        <b style="font-size:11px">${esc(f.titulo)}</b>
        <span style="font-size:10px;color:#c9cdd4">${esc(f.ventana)}</span>
      </div>
      <div style="padding:9px 12px">
        <p style="font-size:10px;color:${C.suave};margin:0 0 6px">${esc(f.descripcion)}</p>
        <ul style="font-size:10.5px;color:${C.texto};margin:0;padding-left:17px;line-height:1.55">
          ${f.iniciativas.map((x) => `<li style="margin:0 0 4px">${esc(x)}</li>`).join('')}
        </ul>
      </div></div>${i === fases.length - 1 ? '' : ''}`
    )
    .join('');
  return out;
}

/**
 * Novedades del periodo: cambios operativos (altas de monitoreo, ajustes).
 * Editable; si el editor no escribe nada, se listan las novedades detectadas
 * automaticamente (equipos que empezaron a reportar en el periodo).
 */
function seccionNovedades(m: ReportMetrics, ov: SeccionesEditables): string {
  if (ov.novedades && ov.novedades.trim() !== '') return rich(ov.novedades);
  if (m.novedades.length === 0) {
    return rich('No se registraron novedades operativas durante el periodo (altas o bajas de equipos, cambios de configuración del monitoreo).');
  }
  return rich('Cambios operativos registrados durante el periodo:') + lista(m.novedades);
}

function seccionAnexos(m: ReportMetrics): string {
  const glosario: [string, string][] = [
    ['Evento de seguridad', 'Cualquier actividad registrada en un equipo o sistema que el monitoreo considera digna de análisis. La mayoría corresponde a operación normal.'],
    ['Caso (incidente)', 'Evento que, tras el análisis, requirió una intervención formal del equipo de seguridad, con seguimiento y cierre documentado.'],
    ['Severidad', 'Nivel de gravedad asignado automáticamente a un evento. La severidad máxima indica que, de confirmarse, podría afectar directamente la operación o la información.'],
    ['Debilidad de software (vulnerabilidad)', 'Falla conocida en un programa instalado, publicada por su fabricante junto con la corrección. Mientras no se aplique la corrección, permanece aprovechable.'],
    ['Configuración segura (hardening)', 'Grado en que un equipo está configurado siguiendo las buenas prácticas internacionales de seguridad, comparado con un estándar de referencia.'],
    ['Doble factor de autenticación', 'Confirmación adicional al ingresar (normalmente en el teléfono del usuario). Impide el acceso incluso si un tercero conoce la contraseña.'],
    ['Firewall perimetral', 'Dispositivo que separa la red interna de Internet y decide qué conexiones se permiten y cuáles se bloquean.'],
    ['Tiempo de reacción', 'Tiempo transcurrido entre la detección de una situación y el inicio de su atención por parte del equipo.'],
  ];
  let out = h3('Anexo A. Glosario para lectura no técnica');
  out += tabla(['Término', 'Significado'], glosario.map(([t, d]) => [`<b>${esc(t)}</b>`, esc(d)]), { anchos: ['26%', '74%'], size: 9.5 });

  out += h3('Anexo B. Nota metodológica');
  out += rich(
    `Los datos de este informe provienen de la plataforma de monitoreo de seguridad de la organización y corresponden al periodo ${m.rangoTexto} (hora de Colombia). El volumen total de actividad se reporta sin filtros. Los conteos por severidad excluyen las reglas previamente identificadas como falsas alarmas, con el fin de no sobredimensionar el riesgo.

El estado de actualización, de configuración segura y de cumplimiento refleja la situación vigente al momento de generar el documento, no un promedio del periodo, ya que se trata de condiciones acumulativas y no de sucesos puntuales.

La comparación con el periodo anterior se realiza contra un intervalo de la misma duración inmediatamente precedente, para que las cifras sean comparables entre sí.`,
    10.5
  );

  out += h3('Anexo C. Controles de seguridad evidenciados (ISO/IEC 27001:2022)');
  out += rich('La operación descrita en este informe constituye evidencia verificable del cumplimiento de los siguientes controles del Anexo A de la norma, útiles ante auditorías internas o externas:', 10.5);
  out += tabla(
    ['Control', 'Denominación', 'Evidencia generada en el periodo'],
    [
      ['A.5.7', 'Inteligencia de amenazas', 'Consulta automática de reputación de las direcciones de Internet involucradas en actividad sospechosa.'],
      ['A.8.15', 'Registro de eventos', `Registro y conservación de ${fmt(m.totalEventos)} eventos de seguridad con trazabilidad completa.`],
      ['A.8.16', 'Actividades de seguimiento', `Monitoreo continuo sobre ${fmt(m.agentesActivos)} de ${fmt(m.agentesTotal)} equipos de la organización.`],
      ['A.8.8', 'Gestión de vulnerabilidades técnicas', `Identificación y priorización de ${fmt(m.postura?.vulnTotal ?? 0)} debilidades de software en los equipos evaluados.`],
      ['A.5.24 – A.5.28', 'Gestión de incidentes', `Detección, análisis, respuesta (${fmt(m.ipsBloqueadas.length)} bloqueo(s)) y documentación de ${fmt(m.gestion.total)} caso(s).`],
    ].map((r) => [`<b>${esc(r[0])}</b>`, esc(r[1]), esc(r[2])]),
    { anchos: ['13%', '25%', '62%'], size: 9.5 }
  );
  return out;
}

// --------------------------------------------------------------------------
// Documento completo
// --------------------------------------------------------------------------

export function buildExecutiveHtml(
  m: ReportMetrics,
  overrides: SeccionesEditables = {},
  opts: { organizacion?: string } = {}
): string {
  const org = opts.organizacion || 'la organización';
  const a = analizar(m, org);
  const sem = SEMAFORO[m.semaforo];
  const logo = logoDataUri();
  const fechaGen = fechaLarga(m.generadoEn);
  const resumen = overrides.resumen || resumenEjecutivo(m, a);

  const indice = [
    'Introducción',
    'Objetivos del informe',
    'Alcance y cobertura',
    'Resultados del periodo',
    'Análisis',
    'Conclusiones',
    'Recomendaciones',
    'Plan de acción',
    'Hoja de ruta',
    'Novedades del periodo',
    'Anexos',
  ];

  const contenido = `
    <!-- Ficha del documento + resumen ejecutivo -->
    <div style="border:1px solid ${C.linea};border-radius:6px;overflow:hidden;margin:0 0 16px;page-break-inside:avoid">
      <div style="background:${C.fondo};padding:9px 14px;border-bottom:1px solid ${C.linea}">
        <b style="font-size:11px;color:${C.tinta};letter-spacing:.4px">FICHA DEL DOCUMENTO</b>
      </div>
      <table style="width:100%;border-collapse:collapse;font-size:10px;color:${C.texto}">
        <tr><td style="padding:5px 14px;width:26%;color:${C.suave}">Periodo evaluado</td><td style="padding:5px 14px"><b>${esc(m.rangoTexto)}</b> (${m.periodo.dias} día${m.periodo.dias === 1 ? '' : 's'})</td></tr>
        <tr><td style="padding:5px 14px;color:${C.suave}">Fecha de emisión</td><td style="padding:5px 14px">${esc(fechaGen)}</td></tr>
        <tr><td style="padding:5px 14px;color:${C.suave}">Elaborado por</td><td style="padding:5px 14px">Centro de Operaciones de Seguridad — HexWatch</td></tr>
        <tr><td style="padding:5px 14px;color:${C.suave}">Dirigido a</td><td style="padding:5px 14px">Dirección General y Comité de Seguridad de la Información</td></tr>
        <tr><td style="padding:5px 14px;color:${C.suave}">Clasificación</td><td style="padding:5px 14px">Uso interno — Confidencial</td></tr>
      </table>
    </div>

    <!-- Semaforo + resumen ejecutivo -->
    <div style="page-break-inside:avoid;margin:0 0 16px">
      <div style="display:flex;align-items:center;gap:12px;padding:11px 15px;background:${sem.color}0f;border-left:5px solid ${sem.color};border-radius:5px">
        <div style="width:16px;height:16px;border-radius:50%;background:${sem.color};flex:none"></div>
        <div style="font-size:11px;color:${C.texto}"><b style="color:${sem.color};letter-spacing:.3px">SITUACIÓN GENERAL: ${sem.label}</b><br>${esc(sem.texto)}</div>
      </div>
    </div>
    <div style="page-break-inside:avoid">
      <h2 style="font-size:15px;color:${C.tinta};margin:0 0 10px;padding:0 0 6px;border-bottom:2px solid ${C.marca}">Resumen ejecutivo</h2>
      ${rich(resumen, 12)}
    </div>

    <!-- Indice -->
    <div style="page-break-inside:avoid;margin:18px 0 0;border-top:1px solid ${C.linea};padding-top:10px">
      <b style="font-size:10px;color:${C.suave};letter-spacing:.5px">CONTENIDO</b>
      <table style="width:100%;border-collapse:collapse;margin-top:6px">
        ${indice.map((t, i) => `<tr><td style="padding:2.5px 0;font-size:10px;color:${C.texto};width:22px">${i + 1}.</td><td style="padding:2.5px 0;font-size:10px;color:${C.texto}">${esc(t)}</td></tr>`).join('')}
      </table>
    </div>

    <div style="page-break-before:always"></div>

    ${h2(1, 'Introducción')}
    ${rich(overrides.introduccion || a.introduccion)}

    ${h2(2, 'Objetivos del informe')}
    ${overrides.objetivos ? rich(overrides.objetivos) : lista(a.objetivos)}

    ${h2(3, 'Alcance y cobertura')}
    ${rich(overrides.alcance || a.alcance)}

    ${h2(4, 'Resultados del periodo')}
    ${seccionResultados(m, a, overrides)}

    ${h2(5, 'Análisis')}
    ${seccionAnalisis(m, a, overrides)}

    ${h2(6, 'Conclusiones')}
    ${overrides.conclusiones ? rich(overrides.conclusiones) : lista(a.conclusiones)}

    ${h2(7, 'Recomendaciones')}
    ${rich('Las siguientes recomendaciones se presentan en orden de prioridad. Cada una responde a una situación concreta identificada en el análisis y busca reducir un riesgo específico, no incorporar tecnología adicional.')}
    ${rich(overrides.recomendaciones || a.recomendaciones)}

    ${h2(8, 'Plan de acción')}
    ${seccionPlanAccion(a, overrides)}

    ${h2(9, 'Hoja de ruta')}
    ${seccionHojaRuta(a, overrides)}

    ${h2(10, 'Novedades del periodo')}
    ${seccionNovedades(m, overrides)}

    ${h2(11, 'Anexos')}
    ${seccionAnexos(m)}

    <div style="margin-top:26px;padding-top:10px;border-top:1px solid ${C.linea};page-break-inside:avoid">
      <table style="width:100%;border-collapse:collapse;font-size:10px;color:${C.texto};margin-top:24px">
        <tr>
          <td style="width:45%;border-top:1px solid ${C.tinta};padding-top:5px;text-align:center">Elaboró<br><span style="color:${C.suave};font-size:9px">Centro de Operaciones de Seguridad</span></td>
          <td style="width:10%"></td>
          <td style="width:45%;border-top:1px solid ${C.tinta};padding-top:5px;text-align:center">Revisó y aprobó<br><span style="color:${C.suave};font-size:9px">Comité de Seguridad de la Información</span></td>
        </tr>
      </table>
    </div>
  `;

  return `<!doctype html><html lang="es"><head><meta charset="utf-8"><title>Informe Gerencial de Seguridad</title><style>
    @page { margin: 0; size: A4; }
    * { box-sizing: border-box; }
    body { font-family: 'Liberation Sans', Arial, Helvetica, sans-serif; margin: 0; color: ${C.tinta}; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    h2, h3 { page-break-after: avoid; }
    table { page-break-inside: avoid; }
    .cover { height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center;
             background: linear-gradient(155deg, #141518 0%, #24262c 55%, ${C.marcaOsc} 190%); color: #fff; page-break-after: always; padding: 0 40px; }
    .cover img { height: 62px; background: #fff; padding: 7px 10px; border-radius: 8px; margin-bottom: 26px; }
    .content { padding: 26px 32px 46px; }
    .footer-band { position: fixed; bottom: 0; left: 0; right: 0; background: ${C.tinta}; color: #c9cdd4; font-size: 8.5px;
                   padding: 5px 32px; display: flex; justify-content: space-between; }
  </style></head><body>
    <div class="cover">
      ${logo ? `<img src="${logo}" alt="HexWatch">` : ''}
      <div style="font-size:12px;letter-spacing:4px;color:#f4a58c">HEXWATCH</div>
      <h1 style="font-size:27px;margin:16px 0 8px;font-weight:700;line-height:1.25">Informe Gerencial de<br>Seguridad de la Información</h1>
      <div style="width:64px;height:3px;background:${C.marca};margin:12px 0 16px"></div>
      <div style="font-size:16px;color:#e5e7eb">${esc(m.periodoLabel)}</div>
      <div style="font-size:11px;color:#9aa1ab;margin-top:4px">${esc(m.rangoTexto)}</div>
      <div style="margin-top:34px;font-size:11.5px;color:#b6bcc5">Centro de Operaciones de Seguridad</div>
      <div style="margin-top:3px;font-size:11.5px;color:#b6bcc5">Dirigido a la Dirección y al Comité de Seguridad de la Información</div>
      <div style="margin-top:22px;font-size:10px;color:#8b929c">Documento alineado a ISO/IEC 27001:2022 &middot; Clasificación: uso interno</div>
      <div style="margin-top:6px;font-size:10px;color:#8b929c">Emitido el ${esc(fechaGen)}</div>
    </div>
    <div class="content">${contenido}</div>
    <div class="footer-band">
      <span>Informe Gerencial de Seguridad &middot; ${esc(m.periodoLabel)}</span>
      <span>HexWatch &middot; Uso interno — Confidencial</span>
    </div>
  </body></html>`;
}

// --------------------------------------------------------------------------
// Textos por defecto expuestos al editor
// --------------------------------------------------------------------------

/** Resumen ejecutivo: lo unico que un directivo leera con seguridad. */
export function resumenEjecutivo(m: ReportMetrics, a?: Analisis): string {
  const an = a ?? analizar(m);
  const criticos = an.hallazgos.filter((h) => h.criticidad === 'critica' || h.criticidad === 'alta');
  const partes: string[] = [];

  const revisadas = m.criticos + m.altos;
  // Frase explicita de revision (estilo informe de gestion). La conclusion
  // absoluta ("ninguno fue incidente") solo se afirma en postura verde; en
  // amarillo/rojo se enuncia la revision sin cerrar el veredicto.
  const fpFrase = revisadas === 0
    ? ''
    : m.semaforo === 'verde'
      ? ` De los ${fmt(revisadas)} evento(s) que requirieron revisión de un analista, tras el análisis se concluyó que ninguno constituyó un incidente de seguridad confirmado.`
      : ` Los ${fmt(revisadas)} evento(s) de mayor severidad fueron revisados y analizados por el equipo.`;
  partes.push(
    `Durante ${m.periodoLabel} la organización mantuvo vigilancia permanente sobre su infraestructura tecnológica, con una cobertura del ${m.coberturaPct} % de los equipos registrados. La plataforma procesó ${fmt(m.totalEventos)} registros de actividad y clasificó ${fmt(m.criticos)} de ellos en severidad máxima.${fpFrase} ${m.gestion.total > 0 ? `El equipo de seguridad gestionó ${fmt(m.gestion.total)} caso(s) formales, de los cuales resolvió el ${m.gestion.tasaResolucion ?? 0} % dentro del periodo.` : 'Ninguna situación requirió abrir un caso formal de atención.'} No se registró interrupción de servicios ni pérdida de información atribuible a un incidente de seguridad.`
  );

  if (criticos.length > 0) {
    partes.push(
      `**Atención requerida.** Se identificaron ${criticos.length} situación(es) de prioridad alta o crítica que dependen de una decisión de la Dirección: ${criticos.slice(0, 3).map((h) => h.titulo.toLowerCase()).join('; ')}. El plan de acción de este informe detalla el responsable, la fecha objetivo y la forma de verificar cada una.`
    );
  } else {
    partes.push(
      '**Sin situaciones críticas pendientes.** No se identificaron riesgos de prioridad alta o crítica sin atender. Las recomendaciones de este informe se orientan a consolidar el nivel alcanzado y a elevar la madurez de la seguridad.'
    );
  }

  const v = m.variacion.criticos;
  const sinBase = !m.anterior || m.anterior.totalEventos === 0;
  partes.push(
    `**Evolución.** ${
      sinBase
        ? 'El periodo equivalente anterior no cuenta con datos en la plataforma, por lo que este informe constituye la línea base contra la cual se medirán los siguientes.'
        : v === null
          ? 'Aún no se dispone de una base comparable suficiente para evaluar la tendencia.'
          : Math.abs(v) < 5
            ? 'La actividad de máxima severidad se mantuvo estable respecto al periodo anterior.'
            : v > 0
              ? `La actividad de máxima severidad aumentó un ${v} % respecto al periodo anterior, lo que amerita seguimiento.`
              : `La actividad de máxima severidad disminuyó un ${Math.abs(v)} % respecto al periodo anterior.`
    }`
  );

  return partes.join('\n\n');
}

export type TextosInforme = { [K in keyof SeccionesEditables]-?: string };

/** Textos por defecto que el editor puede sobrescribir. */
export function textosPorDefecto(m: ReportMetrics, org = 'la organización'): TextosInforme {
  const a = analizar(m, org);
  return {
    resumen: resumenEjecutivo(m, a),
    introduccion: a.introduccion,
    objetivos: a.objetivos.map((o) => `- ${o}`).join('\n'),
    alcance: a.alcance,
    resultados: a.resultados,
    analisis: a.analisis,
    conclusiones: a.conclusiones.map((c) => `- ${c}`).join('\n'),
    recomendaciones: a.recomendaciones,
    planAccion: planAccionATexto(a.planAccion),
    hojaRuta: a.hojaRuta
      .map((f) => `**${f.titulo} (${f.ventana}).** ${f.descripcion}\n\n${f.iniciativas.map((i) => `- ${i}`).join('\n')}`)
      .join('\n\n'),
    novedades: m.novedades.length ? m.novedades.map((n) => `- ${n}`).join('\n') : '',
  };
}

/** Compatibilidad con el flujo anterior (resumen/recomendaciones sueltos). */
export function defaultSummary(m: ReportMetrics): string {
  return resumenEjecutivo(m);
}
export function defaultRecommendations(m: ReportMetrics): string {
  return analizar(m).recomendaciones;
}

// --------------------------------------------------------------------------
// Correo de envio al comite
// --------------------------------------------------------------------------

export function executiveEmailHtml(m: ReportMetrics, resumen: string): string {
  const sem = SEMAFORO[m.semaforo];
  return `<div style="font-family:Arial,Helvetica,sans-serif;max-width:640px;margin:auto;background:#fff;color:${C.texto};border:1px solid ${C.linea};border-radius:10px;overflow:hidden">
    <div style="background:${C.tinta};padding:18px 24px;border-bottom:3px solid ${C.marca}">
      <h2 style="margin:0;font-size:16px;color:#fff">Informe Gerencial de Seguridad de la Información</h2>
      <p style="margin:3px 0 0;font-size:11.5px;color:#b6bcc5">${esc(m.periodoLabel)} &middot; ${esc(m.rangoTexto)}</p>
    </div>
    <div style="padding:22px 24px">
      <div style="display:inline-block;padding:6px 12px;border-radius:6px;background:${sem.color}14;border:1px solid ${sem.color}44;margin-bottom:14px">
        <b style="color:${sem.color};font-size:12px">Situación general: ${sem.label}</b>
        <span style="color:${C.suave};font-size:11px"> — ${esc(sem.texto)}</span>
      </div>
      ${rich(resumen, 12.5)}
      <table style="width:100%;border-collapse:collapse;margin-top:16px;font-size:11px">
        <tr style="background:${C.fondo}"><td style="padding:7px 10px">Actividad analizada</td><td style="padding:7px 10px;text-align:right"><b>${fmt(m.totalEventos)}</b></td></tr>
        <tr><td style="padding:7px 10px">Eventos de severidad máxima</td><td style="padding:7px 10px;text-align:right"><b>${fmt(m.criticos)}</b></td></tr>
        <tr style="background:${C.fondo}"><td style="padding:7px 10px">Casos gestionados</td><td style="padding:7px 10px;text-align:right"><b>${fmt(m.gestion.total)}</b></td></tr>
        <tr><td style="padding:7px 10px">Cobertura de vigilancia</td><td style="padding:7px 10px;text-align:right"><b>${m.coberturaPct} %</b></td></tr>
      </table>
      <p style="font-size:11.5px;color:${C.suave};margin-top:16px">Se adjunta el informe completo en formato PDF (10 secciones, incluye análisis comparativo, plan de acción y hoja de ruta) para el acta del Comité.</p>
    </div>
    <div style="padding:12px 24px;border-top:1px solid ${C.linea};color:${C.suave};font-size:10px;display:flex;justify-content:space-between">
      <span>HexWatch &middot; Centro de Operaciones de Seguridad</span><span>Uso interno — Confidencial</span>
    </div>
  </div>`;
}
