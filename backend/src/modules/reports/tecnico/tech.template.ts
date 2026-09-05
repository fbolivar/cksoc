/**
 * Plantilla HTML/PDF del INFORME TECNICO DE OPERACIONES DE SEGURIDAD.
 *
 * Audiencia: analistas del SOC, administradores de sistemas y de red.
 * A diferencia del informe gerencial, aqui NO se evita el detalle tecnico:
 * se incluyen IDs de regla, hosts, IPs, CVE, tecnicas ATT&CK y las consultas
 * necesarias para reproducir cada hallazgo.
 *
 * Estructura:
 *   Portada · Ficha, resumen tecnico e indice
 *   1. Alcance y telemetria
 *   2. Panorama de detecciones
 *   3. Analisis por dominio
 *   4. Observaciones del analista
 *   5. Hallazgos priorizados (ficha por hallazgo)
 *   6. Plan de accion
 *   7. Hoja de ruta por sprints
 *   8. Anexos
 */
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import type { TechMetrics } from './tech.data';
import {
  analizarTecnico, DOMINIOS, ETIQUETA_SEV,
  type AnalisisTecnico, type HallazgoTecnico, type SevTecnica,
} from './tech.analysis';
import { fechaLarga, etiquetaBucket } from '../executive/periodo';

// --------------------------------------------------------------------------
// Utilidades de presentacion
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
  code: '#f4f5f7',
  marca: '#f0512e',
  marcaOsc: '#b8371a',
  crit: '#b91c1c',
  alta: '#c2410c',
  media: '#b45309',
  baja: '#0f766e',
  info: '#4b5563',
  ok: '#15803d',
};

const COLOR_SEV: Record<SevTecnica, string> = {
  critica: C.crit, alta: C.alta, media: C.media, baja: C.baja, info: C.info,
};

const MONO = "'DejaVu Sans Mono','Liberation Mono',Consolas,monospace";

function logoDataUri(): string | undefined {
  for (const p of [
    resolve(process.cwd(), '../frontend/public/logo-pnnc.png'),
    resolve(process.cwd(), 'assets/logo-pnnc.png'),
  ]) {
    if (existsSync(p)) return `data:image/png;base64,${readFileSync(p).toString('base64')}`;
  }
  return undefined;
}

/** Parrafos, listas y **negrilla**. */
function rich(t: string, size = 11): string {
  const negrilla = (s: string): string => s.replace(/\*\*(.+?)\*\*/g, '<b>$1</b>');
  return String(t ?? '')
    .split(/\n\s*\n/)
    .map((bl) => {
      const lineas = bl.split('\n').map((l) => l.trim()).filter(Boolean);
      if (!lineas.length) return '';
      const esLista = lineas.every((l) => /^([-•*]|\d+[.)])\s+/.test(l));
      if (esLista) {
        return `<ul style="font-size:${size}px;line-height:1.55;color:${C.texto};margin:0 0 9px;padding-left:17px">${lineas
          .map((l) => `<li style="margin:0 0 4px">${negrilla(esc(l.replace(/^([-•*]|\d+[.)])\s+/, '')))}</li>`)
          .join('')}</ul>`;
      }
      return `<p style="font-size:${size}px;line-height:1.6;color:${C.texto};margin:0 0 8px;text-align:justify">${negrilla(esc(bl.replace(/\n/g, ' ')))}</p>`;
    })
    .join('');
}

function h2(n: number, t: string): string {
  return `<h2 style="font-size:14.5px;color:${C.tinta};margin:24px 0 11px;padding:0 0 6px;border-bottom:2px solid ${C.marca};page-break-after:avoid">
    <span style="display:inline-block;min-width:22px;color:${C.marca}">${n}.</span>${esc(t)}</h2>`;
}
function h3(t: string): string {
  return `<h3 style="font-size:11.5px;color:${C.tinta};margin:15px 0 6px;page-break-after:avoid">${esc(t)}</h3>`;
}
function nota(t: string): string {
  return `<p style="font-size:9px;color:${C.suave};margin:3px 0 11px;font-style:italic">${esc(t)}</p>`;
}
function mono(t: string): string {
  return `<span style="font-family:${MONO};font-size:9.5px;background:${C.code};padding:1px 4px;border-radius:3px">${esc(t)}</span>`;
}
function pill(t: string, color: string): string {
  return `<span style="display:inline-block;padding:1px 6px;border-radius:9px;background:${color}1a;color:${color};font-size:8.5px;font-weight:700;white-space:nowrap">${esc(t)}</span>`;
}
function bloqueCodigo(t: string): string {
  return `<pre style="font-family:${MONO};font-size:8px;line-height:1.4;background:${C.code};border:1px solid ${C.linea};border-left:3px solid ${C.suave};border-radius:4px;padding:8px 10px;margin:6px 0 0;white-space:pre-wrap;word-break:break-word;color:${C.texto};page-break-inside:avoid">${esc(t)}</pre>`;
}

interface Kpi { valor: string; etiqueta: string; pie?: string; color?: string }

function kpiGrid(kpis: Kpi[], porFila = 4): string {
  const celdas = kpis.map(
    (k) => `<td style="width:${Math.floor(100 / porFila)}%;padding:3px;vertical-align:top">
      <div style="border:1px solid ${C.linea};border-left:3px solid ${k.color ?? C.marca};background:#fff;padding:9px 11px;border-radius:4px">
        <div style="font-size:18px;font-weight:700;color:${k.color ?? C.tinta};line-height:1.15">${esc(k.valor)}</div>
        <div style="font-size:8.5px;color:${C.texto};margin-top:3px;font-weight:700;text-transform:uppercase;letter-spacing:.3px">${esc(k.etiqueta)}</div>
        ${k.pie ? `<div style="font-size:8px;color:${C.suave};margin-top:2px;line-height:1.35">${esc(k.pie)}</div>` : ''}
      </div></td>`
  );
  const filas: string[] = [];
  for (let i = 0; i < celdas.length; i += porFila) {
    const g = celdas.slice(i, i + porFila);
    while (g.length < porFila) g.push('<td style="padding:3px"></td>');
    filas.push(`<tr>${g.join('')}</tr>`);
  }
  return `<table style="width:100%;border-collapse:collapse;margin:5px 0 13px;page-break-inside:avoid">${filas.join('')}</table>`;
}

function tabla(cols: string[], filas: string[][], opts: { anchos?: string[]; size?: number } = {}): string {
  if (filas.length === 0) return '';
  const size = opts.size ?? 9.5;
  const th = cols
    .map((c, i) => `<th style="padding:6px 8px;border-bottom:2px solid ${C.tinta};text-align:left;font-size:${size}px;color:${C.tinta};${opts.anchos?.[i] ? `width:${opts.anchos[i]};` : ''}">${c}</th>`)
    .join('');
  const tb = filas
    .map((f, ri) => `<tr style="background:${ri % 2 ? C.fondo : '#fff'}">${f
      .map((v) => `<td style="padding:5px 8px;border-bottom:1px solid ${C.linea};font-size:${size}px;color:${C.texto};vertical-align:top">${v}</td>`)
      .join('')}</tr>`)
    .join('');
  return `<table style="width:100%;border-collapse:collapse;margin:5px 0 13px;page-break-inside:avoid"><thead><tr>${th}</tr></thead><tbody>${tb}</tbody></table>`;
}

/** Barra horizontal proporcional para comparativas simples. */
function barra(pct: number, color = C.marca): string {
  const w = Math.max(0, Math.min(100, pct));
  return `<div style="background:${C.linea};border-radius:2px;height:7px;width:100%;overflow:hidden"><div style="background:${color};height:7px;width:${w}%"></div></div>`;
}

// --------------------------------------------------------------------------
// Graficos
// --------------------------------------------------------------------------

function graficoSerie(m: TechMetrics): string {
  const s = m.serie;
  if (s.length < 2) return nota('El periodo no tiene suficientes tramos para representar la evolución.');
  const W = 640, H = 165, padL = 42, padR = 10, padT = 14, padB = 24;
  const max = Math.max(...s.map((x) => x.total), 1);
  const bw = (W - padL - padR) / s.length;
  const picos = new Set(m.picos.map((p) => p.ts));
  const barras = s.map((x, i) => {
    const hgt = ((H - padT - padB) * x.total) / max;
    const y = H - padB - hgt;
    const xc = padL + i * bw + bw * 0.15;
    const w = bw * 0.7;
    const crit = x.criticos > 0 ? ((H - padT - padB) * x.criticos) / max : 0;
    const color = picos.has(x.ts) ? C.crit : C.marca;
    return `<rect x="${xc.toFixed(1)}" y="${y.toFixed(1)}" width="${w.toFixed(1)}" height="${Math.max(hgt, 0.6).toFixed(1)}" fill="${color}" opacity="${picos.has(x.ts) ? 0.9 : 0.72}"/>` +
      (crit > 0 ? `<rect x="${xc.toFixed(1)}" y="${(H - padB - crit).toFixed(1)}" width="${w.toFixed(1)}" height="${Math.max(crit, 1.2).toFixed(1)}" fill="${C.crit}"/>` : '');
  }).join('');
  const paso = Math.max(1, Math.ceil(s.length / 14));
  const ejeX = s.map((x, i) => (i % paso === 0
    ? `<text x="${(padL + i * bw + bw / 2).toFixed(1)}" y="${H - 8}" font-size="7.5" fill="${C.suave}" text-anchor="middle">${esc(etiquetaBucket(x.ts, m.periodo.granularidad))}</text>`
    : '')).join('');
  const ejeY = [0, 0.5, 1].map((f) => {
    const y = H - padB - (H - padT - padB) * f;
    return `<line x1="${padL}" y1="${y}" x2="${W - padR}" y2="${y}" stroke="${C.linea}"/><text x="${padL - 5}" y="${y + 3}" font-size="7.5" fill="${C.suave}" text-anchor="end">${fmt(Math.round(max * f))}</text>`;
  }).join('');
  return `<div style="page-break-inside:avoid"><svg width="100%" viewBox="0 0 ${W} ${H}" style="max-width:100%">${ejeY}${barras}${ejeX}</svg>
    <div style="font-size:8.5px;color:${C.suave};margin-top:2px">
      <span style="display:inline-block;width:9px;height:9px;background:${C.marca};opacity:.72;vertical-align:-1px"></span> Eventos &nbsp;
      <span style="display:inline-block;width:9px;height:9px;background:${C.crit};vertical-align:-1px"></span> Nivel ≥ 12 / tramo marcado como pico
    </div></div>`;
}

// --------------------------------------------------------------------------
// Secciones
// --------------------------------------------------------------------------

function seccionAlcance(m: TechMetrics): string {
  const s = m.salud;
  let out = rich(
    `El informe cubre la telemetría recibida por el manager de Wazuh entre ${m.periodo.rangoTexto}. La ventana se evalúa en hora de Colombia y los cortes son reproducibles: cualquier consulta de este documento devuelve los mismos resultados si se ejecuta con el mismo rango.`
  );

  out += tabla(
    ['Parámetro del informe', 'Valor'],
    [
      ['Ventana analizada', `${esc(m.periodo.rangoTexto)}`],
      ['Granularidad de la serie', esc(m.periodo.granularidad)],
      ['Índice consultado', mono(`${process.env.WAZUH_ALERTS_INDEX ?? 'wazuh-alerts-*'}`)],
      ['Agentes registrados / activos', `${fmt(m.agentes.total)} / ${fmt(m.agentes.activos)}`],
      ['Reglas distintas disparadas', fmt(m.reglasDistintas)],
      ['Reglas propias cargadas', fmt(m.reglasPropias.length)],
      ['Supresiones activas', fmt(m.supresiones.length)],
    ],
    { anchos: ['32%', '68%'] }
  );

  out += h3('Estado de la telemetría');
  const filas: string[][] = [
    ['Tramos sin ningún evento', `${fmt(s.bucketsVacios)} de ${fmt(s.bucketsTotales)}`, s.bucketsVacios === 0 ? 'Ingesta continua.' : 'Revisar interrupciones de ingesta.'],
    ['Mayor tramo sin datos', s.mayorHueco ? `${s.mayorHueco.horas} h desde ${esc(s.mayorHueco.desde)}` : '—', s.mayorHueco ? 'Ventana ciega: sin detección posible.' : 'Sin interrupciones relevantes.'],
    ['Agentes activos sin eventos', fmt(s.agentesSinEventos.length), s.agentesSinEventos.length ? esc(s.agentesSinEventos.join(', ')) : 'Todos los agentes activos reportaron.'],
    ['Agentes desconectados', fmt(s.agentesDesconectados.length), s.agentesDesconectados.length ? esc(s.agentesDesconectados.map((a) => a.agente).join(', ')) : 'Ninguno.'],
  ];
  out += tabla(['Indicador', 'Valor', 'Lectura'], filas, { anchos: ['26%', '22%', '52%'] });

  if (s.versionesAgente.length) {
    out += h3('Versiones del agente en el parque');
    out += tabla(
      ['Versión', 'Agentes'],
      s.versionesAgente.map((v) => [mono(v.version), fmt(v.agentes)]),
      { anchos: ['70%', '30%'] }
    );
  }

  out += nota('Los conteos por severidad excluyen las reglas listadas en REPORT_EXCLUDE_RULES (falsos positivos conocidos). El volumen total se reporta sin filtros.');
  return out;
}

function seccionPanorama(m: TechMetrics): string {
  const kpis: Kpi[] = [
    { valor: fmt(m.total), etiqueta: 'Eventos totales', pie: 'sin filtrar' },
    { valor: fmt(m.criticos), etiqueta: 'Nivel ≥ 12', pie: 'severidad crítica', color: m.criticos > 0 ? C.crit : C.ok },
    { valor: fmt(m.altos), etiqueta: 'Nivel 8–11', pie: 'severidad alta', color: m.altos > 0 ? C.alta : C.ok },
    { valor: fmt(m.reglasDistintas), etiqueta: 'Reglas distintas', pie: 'disparadas en el periodo' },
    { valor: fmt(m.mitre.tecnicas.length), etiqueta: 'Técnicas ATT&CK', pie: 'observadas' },
    { valor: fmt(m.ipsExternas.length), etiqueta: 'IP públicas', pie: 'con actividad relevante' },
    { valor: fmt(m.fim.total), etiqueta: 'Cambios FIM', pie: `${m.fim.modified} modificaciones` },
    { valor: fmt(m.gestion.total), etiqueta: 'Casos abiertos', pie: `${m.gestion.resueltos} resueltos` },
  ];
  let out = kpiGrid(kpis);

  // Distribución por nivel
  out += h3('Distribución por nivel de regla');
  const maxNivel = Math.max(...m.porNivel.map((n) => n.conteo), 1);
  out += tabla(
    ['Banda', 'Rango', 'Eventos', '% del total', 'Distribución'],
    m.porNivel.map((n) => [
      `<b>${esc(n.banda)}</b>`,
      mono(n.rango),
      fmt(n.conteo),
      `${m.total ? Math.round((n.conteo / m.total) * 1000) / 10 : 0} %`,
      barra((n.conteo / maxNivel) * 100, n.banda === 'Crítica' ? C.crit : n.banda === 'Alta' ? C.alta : C.marca),
    ]),
    { anchos: ['14%', '16%', '14%', '14%', '42%'] }
  );

  // Serie
  out += h3('Evolución del volumen');
  out += graficoSerie(m);
  if (m.picos.length) {
    out += tabla(
      ['Tramo con pico', 'Eventos', 'Veces la mediana'],
      m.picos.map((p) => [esc(p.ts), fmt(p.total), `${p.vecesMedia}×`]),
      { anchos: ['52%', '24%', '24%'] }
    );
    out += nota('Se marca como pico todo tramo que supere el doble de la mediana de tramos con datos. Un pico no es un incidente, pero siempre merece una explicación registrada.');
  }

  // Top reglas
  out += h3('Reglas con mayor volumen');
  out += tabla(
    ['ID', 'Nivel', 'Descripción', 'Eventos', '% vol.', 'Agentes', 'ATT&CK'],
    m.topReglas.map((r) => [
      mono(r.ruleId),
      `<b style="color:${r.nivel >= 12 ? C.crit : r.nivel >= 8 ? C.alta : C.texto}">${r.nivel}</b>`,
      esc(r.descripcion),
      fmt(r.conteo),
      `${r.pctVolumen} %`,
      String(r.agentes),
      r.mitre.length ? mono(r.mitre.slice(0, 2).join(', ')) : '—',
    ]),
    { anchos: ['7%', '6%', '39%', '11%', '9%', '8%', '20%'], size: 9 }
  );

  // Top agentes
  out += h3('Agentes con mayor actividad');
  out += tabla(
    ['Agente', 'Eventos', 'Nivel ≥ 12', 'Nivel 8–11', 'Reglas distintas'],
    m.topAgentes.map((a) => [
      `<b>${esc(a.agente)}</b>`,
      fmt(a.total),
      a.criticos ? `<b style="color:${C.crit}">${fmt(a.criticos)}</b>` : '0',
      a.altos ? `<span style="color:${C.alta}">${fmt(a.altos)}</span>` : '0',
      fmt(a.reglasDistintas),
    ]),
    { anchos: ['36%', '16%', '16%', '16%', '16%'] }
  );
  out += nota('Un volumen alto no implica compromiso: normalmente refleja que el host presta más servicios. Lo relevante es la proporción de eventos de nivel alto y la diversidad de reglas distintas.');

  return out;
}

function seccionDominios(m: TechMetrics): string {
  let out = '';

  // --- Accesos
  out += h3('3.1 Accesos y autenticación');
  if (m.auth.fallos + m.auth.exitos === 0) {
    out += rich('No se registraron eventos de autenticación en la ventana. Conviene verificar que los decoders de autenticación estén activos en los agentes.');
  } else {
    out += rich(
      `${fmt(m.auth.fallos)} fallos y ${fmt(m.auth.exitos)} autenticaciones exitosas (ratio de fallo del ${m.auth.ratioFallo ?? 0} %).`
    );
    if (m.auth.usuariosAtacados.length) {
      out += tabla(
        ['Cuenta objetivo', 'Intentos fallidos'],
        m.auth.usuariosAtacados.slice(0, 8).map((u) => [mono(u.usuario), fmt(u.fallos)]),
        { anchos: ['70%', '30%'] }
      );
    }
    if (m.auth.ipsOrigen.length) {
      out += tabla(
        ['IP origen', 'Ámbito', 'País', 'Fallos'],
        m.auth.ipsOrigen.slice(0, 8).map((i) => [
          mono(i.ip),
          i.publica ? pill('pública', C.alta) : pill('interna', C.baja),
          esc(i.pais ?? '—'),
          fmt(i.fallos),
        ]),
        { anchos: ['34%', '20%', '26%', '20%'] }
      );
    }
  }

  // --- Exposición
  out += h3('3.2 Exposición y perímetro');
  if (m.ipsExternas.length) {
    out += tabla(
      ['IP pública', 'País', 'Eventos', 'Nivel máx', 'Reglas', 'Agentes alcanzados', 'Regla de ejemplo'],
      m.ipsExternas.map((i) => [
        mono(i.ip),
        esc(i.pais ?? '—'),
        fmt(i.conteo),
        `<b style="color:${i.nivelMax >= 12 ? C.crit : i.nivelMax >= 8 ? C.alta : C.texto}">${i.nivelMax}</b>`,
        String(i.reglasDistintas),
        esc(i.agentes.join(', ') || '—'),
        esc(i.reglaEjemplo.slice(0, 60)),
      ]),
      { anchos: ['13%', '11%', '9%', '8%', '7%', '19%', '33%'], size: 9 }
    );
  } else {
    out += rich('No se observó actividad desde direcciones públicas en la ventana analizada.');
  }

  const expuestos = m.puertos.filter((p) => ['0.0.0.0', '::', '*'].includes(p.ip));
  if (expuestos.length) {
    out += tabla(
      ['Agente', 'Puerto', 'Transporte', 'Proceso'],
      expuestos.slice(0, 14).map((p) => [esc(p.agent), mono(String(p.port)), esc(p.transport), esc(p.process || '—')]),
      { anchos: ['32%', '14%', '16%', '38%'] }
    );
    out += nota('Servicios enlazados a todas las interfaces (0.0.0.0). Estado actual del inventario, no acotado al periodo.');
  }

  if (m.bloqueos.length) {
    out += tabla(
      ['IP bloqueada', 'País', 'Motivo', 'Fecha'],
      m.bloqueos.slice(0, 10).map((b) => [mono(b.ip), esc(b.pais ?? '—'), esc(b.motivo ?? '—'), esc(new Date(b.ts).toLocaleString('es-CO'))]),
      { anchos: ['20%', '16%', '42%', '22%'] }
    );
    out += nota('Bloqueos aplicados en el firewall perimetral durante el periodo, con su registro de auditoría.');
  }

  // --- MITRE
  out += h3('3.3 Cobertura MITRE ATT&CK');
  if (m.mitre.tecnicas.length) {
    out += tabla(
      ['Técnica', 'Nombre', 'Tácticas', 'Eventos', 'Nivel máx'],
      m.mitre.tecnicas.map((t) => [
        mono(t.id),
        esc(t.nombre || '—'),
        esc(t.tacticas.join(', ')),
        fmt(t.conteo),
        String(t.nivelMax),
      ]),
      { anchos: ['12%', '34%', '30%', '12%', '12%'] }
    );
  } else {
    out += rich('Ningún evento del periodo trae mapeo a técnicas de ATT&CK.');
  }
  if (m.cobertura) {
    const cob = m.cobertura;
    out += tabla(
      ['Táctica', 'Técnicas detectadas', 'Técnicas del marco', 'Cobertura', 'Alertas'],
      cob.tactics
        .slice()
        .sort((a, b) => a.coverage - b.coverage)
        .map((t) => [
          esc(t.tactic),
          String(t.detected),
          String(t.total),
          `${t.detected === 0 ? pill('punto ciego', C.crit) : ''} ${barra(t.coverage, t.coverage === 0 ? C.crit : C.marca)}`,
          fmt(t.alerts),
        ]),
      { anchos: ['30%', '14%', '14%', '30%', '12%'] }
    );
    out += nota(`Cobertura calculada sobre los últimos ${cob.days} días: ${cob.tacticsCovered} de ${cob.tacticsTotal} tácticas con al menos una detección; ${cob.techniquesDetected} técnicas distintas observadas.`);
  }

  // --- FIM
  out += h3('3.4 Integridad de archivos');
  if (m.fim.total > 0) {
    out += rich(`${fmt(m.fim.total)} cambios registrados: ${m.fim.added} altas, ${m.fim.modified} modificaciones y ${m.fim.deleted} borrados.`);
    out += tabla(
      ['', 'Agente', 'Evento', 'Ruta', 'Usuario', 'Nivel'],
      m.fim.cambios.map((c) => [
        c.critico ? pill('sensible', C.crit) : '',
        esc(c.agente),
        esc(c.evento),
        mono(c.ruta.slice(0, 70)),
        esc(c.usuario || '—'),
        String(c.nivel),
      ]),
      { anchos: ['9%', '15%', '10%', '43%', '15%', '8%'], size: 9 }
    );
  } else {
    out += rich('No se registraron cambios de integridad de archivos en la ventana. Verificar que el módulo syscheck esté habilitado y con directorios configurados.');
  }

  // --- Vulnerabilidades
  out += h3('3.5 Vulnerabilidades (estado actual)');
  if (m.vuln) {
    const v = m.vuln;
    out += kpiGrid([
      { valor: `${v.resumen.total >= 10_000 ? '≥ ' : ''}${fmt(v.resumen.total)}`, etiqueta: 'Detecciones', pie: `${fmt(v.resumen.cves)} CVE distintos` },
      { valor: fmt(v.resumen.critical), etiqueta: 'Críticas', color: v.resumen.critical ? C.crit : C.ok },
      { valor: fmt(v.resumen.high), etiqueta: 'Altas', color: v.resumen.high ? C.alta : C.ok },
      { valor: fmt(v.resumen.kev), etiqueta: 'En catálogo KEV', pie: 'explotación activa', color: v.resumen.kev ? C.crit : C.ok },
    ]);
    if (v.topCve?.length) {
      out += tabla(
        ['CVE', 'Severidad', 'CVSS', 'EPSS', 'KEV', 'Prioridad', 'Hosts'],
        v.topCve.slice(0, 12).map((c) => [
          mono(c.cve),
          esc(c.severity),
          c.score != null ? String(c.score) : '—',
          c.epss != null ? `${(c.epss * 100).toFixed(1)} %` : '—',
          c.inKev ? pill('sí', C.crit) : '—',
          `<b>${c.priority}</b>`,
          fmt(c.count),
        ]),
        { anchos: ['20%', '13%', '10%', '11%', '10%', '13%', '13%'], size: 9 }
      );
      out += nota('Prioridad = CVSS ponderado + presencia en KEV + probabilidad de explotación (EPSS). Es el orden en el que conviene parchear.');
    }
    if (v.porAgente?.length) {
      out += tabla(
        ['Host', 'Total', 'Críticas', 'Altas'],
        v.porAgente.slice(0, 10).map((a) => [`<b>${esc(a.agent)}</b>`, fmt(a.total), fmt(a.critical), fmt(a.high)]),
        { anchos: ['46%', '18%', '18%', '18%' ] }
      );
    }
  } else {
    out += rich('El módulo de vulnerabilidades no devolvió datos en esta ejecución.');
  }

  // --- SCA
  out += h3('3.6 Configuración segura (SCA / CIS)');
  if (m.sca) {
    const s = m.sca;
    out += rich(`Score promedio ${s.resumen.scorePromedio} % sobre ${fmt(s.resumen.totalChecks)} controles evaluados en ${s.resumen.agentesEvaluados} host(s): ${fmt(s.resumen.pass)} superados y ${fmt(s.resumen.fail)} fallidos.`);
    out += tabla(
      ['Host', 'Política', 'Score', 'Superados', 'Fallidos'],
      [...s.agentes].sort((a, b) => a.score - b.score).slice(0, 10).map((a) => [
        `<b>${esc(a.agent)}</b>`,
        esc(a.policy),
        `<b style="color:${a.score < 60 ? C.crit : a.score < 80 ? C.alta : C.ok}">${a.score} %</b>`,
        fmt(a.pass),
        fmt(a.fail),
      ]),
      { anchos: ['22%', '38%', '14%', '13%', '13%'] }
    );
    if (s.topFallidos.length) {
      out += tabla(
        ['Control fallido', 'Hosts', 'Remediación'],
        s.topFallidos.slice(0, 8).map((c) => [esc(c.title), fmt(c.count), esc((c.remediation || '—').slice(0, 300))]),
        { anchos: ['34%', '8%', '58%'], size: 9 }
      );
    }
  } else {
    out += rich('El módulo SCA no devolvió datos en esta ejecución.');
  }

  // --- Inteligencia y comportamiento
  out += h3('3.7 Inteligencia de amenazas y comportamiento');
  if (m.iocMatches.length) {
    out += tabla(
      ['Tipo', 'Indicador', 'Fuente', 'Alertas', 'Agente', 'Última vez'],
      m.iocMatches.slice(0, 10).map((i) => [
        esc(i.type), mono(i.value), esc(i.source), fmt(i.alertCount), esc(i.agent || '—'), esc(i.lastSeen),
      ]),
      { anchos: ['10%', '26%', '16%', '10%', '16%', '22%'], size: 9 }
    );
  } else {
    out += rich('Sin coincidencias con los indicadores de compromiso cargados durante el periodo.');
  }
  if (m.anomalias.length) {
    out += tabla(
      ['Detector', 'Entidad', 'Severidad', 'Score', 'Descripción', 'Estado'],
      m.anomalias.map((a) => [
        mono(a.detector), esc(a.entidad),
        pill(a.severidad, a.severidad === 'critica' ? C.crit : a.severidad === 'alta' ? C.alta : C.media),
        String(a.score), esc(a.titulo), esc(a.estado),
      ]),
      { anchos: ['16%', '18%', '11%', '8%', '35%', '12%'], size: 9 }
    );
  }

  return out;
}

/** Ficha completa por hallazgo: evidencia, impacto, remediacion y consulta. */
function fichaHallazgo(x: HallazgoTecnico, n: number): string {
  const col = COLOR_SEV[x.severidad];
  return `<div style="border:1px solid ${C.linea};border-left:4px solid ${col};border-radius:5px;margin:0 0 12px;page-break-inside:avoid">
    <div style="background:${C.fondo};padding:7px 11px;border-bottom:1px solid ${C.linea}">
      <table style="width:100%;border-collapse:collapse"><tr>
        <td style="font-size:11.5px;color:${C.tinta}"><b>H-${String(n).padStart(2, '0')} · ${esc(x.titulo)}</b></td>
        <td style="text-align:right;white-space:nowrap">${pill(ETIQUETA_SEV[x.severidad], col)} ${pill(DOMINIOS[x.dominio], C.info)}</td>
      </tr></table>
    </div>
    <div style="padding:9px 11px">
      <p style="font-size:10px;margin:0 0 6px;color:${C.texto};line-height:1.55"><b style="color:${C.tinta}">Evidencia.</b> ${esc(x.evidencia)}</p>
      ${x.detalle.length ? `<ul style="font-family:${MONO};font-size:8.5px;color:${C.texto};margin:0 0 7px;padding-left:15px;line-height:1.5">${x.detalle.slice(0, 10).map((d) => `<li style="margin:0 0 2px">${esc(d)}</li>`).join('')}</ul>` : ''}
      <p style="font-size:10px;margin:0 0 6px;color:${C.texto};line-height:1.55"><b style="color:${C.tinta}">Impacto.</b> ${esc(x.impacto)}</p>
      <p style="font-size:10px;margin:0 0 3px;color:${C.tinta}"><b>Remediación</b></p>
      <ol style="font-size:10px;color:${C.texto};margin:0 0 7px;padding-left:16px;line-height:1.55">${x.remediacion.map((r) => `<li style="margin:0 0 3px">${esc(r)}</li>`).join('')}</ol>
      <table style="width:100%;border-collapse:collapse;font-size:9px;color:${C.texto};background:${C.fondo};border-radius:4px">
        <tr>
          <td style="padding:5px 8px"><span style="color:${C.suave}">Responsable:</span> <b>${esc(x.responsable)}</b></td>
          <td style="padding:5px 8px"><span style="color:${C.suave}">Esfuerzo:</span> <b>${esc(x.esfuerzo)}</b></td>
          <td style="padding:5px 8px"><span style="color:${C.suave}">Confianza:</span> <b>${esc(x.confianza)}</b></td>
        </tr>
        <tr><td colspan="3" style="padding:0 8px 5px"><span style="color:${C.suave}">Criterio de cierre:</span> ${esc(x.aceptacion)}</td></tr>
      </table>
      ${x.consulta ? `<p style="font-size:9px;margin:7px 0 0;color:${C.suave}">Consulta para reproducir:</p>${bloqueCodigo(x.consulta)}` : ''}
    </div>
  </div>`;
}

function seccionPlan(m: TechMetrics, a: AnalisisTecnico): string {
  if (!a.plan.length) return rich('No se derivaron acciones del análisis: no se identificaron hallazgos en el periodo.');
  let out = rich(
    'Cada acción proviene de un hallazgo concreto de la sección anterior. Las fechas objetivo se calculan desde la emisión del informe y son ajustables según la capacidad real del equipo; el criterio de corte ante falta de capacidad debe ser la severidad.'
  );
  out += tabla(
    ['#', 'Acción', 'Dominio', 'Sev.', 'Responsable', 'Esfuerzo', 'Fecha objetivo', 'Criterio de cierre'],
    a.plan.map((p) => [
      String(p.n),
      `<b>${esc(p.accion)}</b>`,
      esc(DOMINIOS[p.dominio]),
      pill(ETIQUETA_SEV[p.severidad], COLOR_SEV[p.severidad]),
      esc(p.responsable),
      esc(p.esfuerzo),
      esc(p.plazo),
      esc(p.aceptacion),
    ]),
    { anchos: ['3%', '25%', '12%', '7%', '13%', '8%', '12%', '20%'], size: 8.5 }
  );
  void m;
  return out;
}

function seccionHojaRuta(a: AnalisisTecnico): string {
  if (!a.hojaRuta.length) return '';
  let out = rich('Las acciones se agrupan en sprints para poder planificarlas. El orden no es negociable entre fases: primero se recupera la visibilidad y se contiene lo explotable, después se reduce la superficie y solo entonces se amplía la cobertura de detección.');
  out += a.hojaRuta.map((f) => `<div style="page-break-inside:avoid;margin:0 0 10px;border:1px solid ${C.linea};border-radius:5px;overflow:hidden">
    <div style="background:${C.tinta};color:#fff;padding:6px 11px">
      <table style="width:100%;border-collapse:collapse"><tr>
        <td style="font-size:10.5px"><b>${esc(f.titulo)}</b></td>
        <td style="text-align:right;font-size:9.5px;color:#c9cdd4">${esc(f.ventana)} · ${f.items.length} acción(es)</td>
      </tr></table>
    </div>
    <div style="padding:8px 11px">
      <p style="font-size:9.5px;color:${C.suave};margin:0 0 6px">${esc(f.objetivo)}</p>
      <table style="width:100%;border-collapse:collapse">
        ${f.items.map((i) => `<tr>
          <td style="padding:3px 0;width:66px;vertical-align:top">${pill(ETIQUETA_SEV[i.severidad], COLOR_SEV[i.severidad])}</td>
          <td style="padding:3px 0;font-size:10px;color:${C.texto}">${esc(i.accion)}<span style="color:${C.suave}"> — ${esc(i.dominio)}</span></td>
        </tr>`).join('')}
      </table>
    </div></div>`).join('');
  return out;
}

function seccionAnexos(m: TechMetrics, a: AnalisisTecnico): string {
  let out = h3('Anexo A. Indicadores observados');
  if (a.iocs.length) {
    out += tabla(
      ['Tipo', 'Indicador', 'Contexto'],
      a.iocs.map((i) => [esc(i.tipo), mono(i.valor), esc(i.contexto)]),
      { anchos: ['16%', '26%', '58%'], size: 9 }
    );
    out += nota('Lista para búsqueda retrospectiva o para carga en el módulo de Threat Intel. La presencia de un indicador NO implica compromiso: implica que merece verificación.');
  } else {
    out += rich('No se extrajeron indicadores relevantes en el periodo.');
  }

  out += h3('Anexo B. Inventario de agentes');
  if (m.inventario.length) {
    out += tabla(
      ['Agente', 'IP', 'Estado', 'Sistema operativo', 'Versión', 'Último contacto'],
      m.inventario.slice(0, 40).map((ag) => [
        `<b>${esc(ag.name)}</b>`,
        mono(ag.ip || '—'),
        ag.status === 'active' ? pill('activo', C.ok) : pill(ag.status, C.alta),
        esc(ag.os || '—'),
        mono(ag.version || '—'),
        esc(ag.lastKeepAlive || '—'),
      ]),
      { anchos: ['17%', '13%', '11%', '27%', '14%', '18%'], size: 8.5 }
    );
  }

  if (m.supresiones.length) {
    out += h3('Anexo C. Supresiones activas');
    out += tabla(
      ['Regla', 'Campo', 'Valor', 'Comentario'],
      m.supresiones.map((s) => [mono(s.targetRuleId), mono(s.field), mono(s.value), esc(s.comment)]),
      { anchos: ['12%', '22%', '26%', '40%'], size: 9 }
    );
    out += nota('Toda supresión reduce deliberadamente la detección. Deben revisarse periódicamente: una supresión que se olvida se convierte en un punto ciego permanente.');
  }

  out += h3('Anexo D. Glosario técnico');
  out += tabla(
    ['Término', 'Definición'],
    ([
      ['Nivel de regla', 'Severidad asignada por Wazuh (0–15). ≥ 12 se considera crítico; 8–11 alto.'],
      ['KEV', 'Known Exploited Vulnerabilities: catálogo de CISA con vulnerabilidades cuya explotación se ha observado en ataques reales.'],
      ['EPSS', 'Exploit Prediction Scoring System: probabilidad estimada de que un CVE sea explotado en los próximos 30 días.'],
      ['SCA', 'Security Configuration Assessment: evaluación de la configuración del host contra un estándar (CIS Benchmark).'],
      ['FIM / syscheck', 'Monitoreo de integridad de archivos: detecta altas, modificaciones y borrados en rutas vigiladas.'],
      ['MTTA / MTTR', 'Tiempo medio hasta la primera atención y hasta la resolución de un caso.'],
      ['Supresión', 'Filtro que descarta eventos de una regla para un valor concreto de un campo, sin desactivar la regla completa.'],
      ['Punto ciego (ATT&CK)', 'Táctica del marco sin ninguna técnica detectada: actividad adversaria posible sin generar alerta.'],
    ] as [string, string][]).map(([t, d]) => [`<b>${esc(t)}</b>`, esc(d)]),
    { anchos: ['22%', '78%'], size: 9 }
  );

  return out;
}

// --------------------------------------------------------------------------
// Documento
// --------------------------------------------------------------------------

export function buildTechnicalHtml(m: TechMetrics): string {
  const a = analizarTecnico(m);
  const logo = logoDataUri();
  const fechaGen = fechaLarga(m.generadoEn);

  const criticos = a.hallazgos.filter((x) => x.severidad === 'critica').length;
  const altos = a.hallazgos.filter((x) => x.severidad === 'alta').length;
  const semColor = criticos > 0 ? C.crit : altos > 0 ? C.alta : C.ok;
  const semTexto = criticos > 0
    ? `${criticos} hallazgo(s) crítico(s) requieren acción en 24–72 h`
    : altos > 0
      ? `${altos} hallazgo(s) de severidad alta para el Sprint 1`
      : 'Sin hallazgos críticos ni altos en el periodo';

  const indice = [
    'Alcance y telemetría',
    'Panorama de detecciones',
    'Análisis por dominio',
    'Observaciones del analista',
    'Hallazgos priorizados',
    'Plan de acción',
    'Hoja de ruta por sprints',
    'Anexos',
  ];

  const contenido = `
    <div style="border:1px solid ${C.linea};border-radius:6px;overflow:hidden;margin:0 0 14px;page-break-inside:avoid">
      <div style="background:${C.fondo};padding:8px 13px;border-bottom:1px solid ${C.linea}">
        <b style="font-size:10.5px;color:${C.tinta};letter-spacing:.4px">FICHA DEL INFORME</b>
      </div>
      <table style="width:100%;border-collapse:collapse;font-size:9.5px;color:${C.texto}">
        <tr><td style="padding:4px 13px;width:26%;color:${C.suave}">Ventana analizada</td><td style="padding:4px 13px"><b>${esc(m.periodo.rangoTexto)}</b></td></tr>
        <tr><td style="padding:4px 13px;color:${C.suave}">Emitido</td><td style="padding:4px 13px">${esc(fechaGen)}</td></tr>
        <tr><td style="padding:4px 13px;color:${C.suave}">Alcance</td><td style="padding:4px 13px">${fmt(m.agentes.activos)} de ${fmt(m.agentes.total)} agentes activos · ${fmt(m.total)} eventos · ${fmt(m.reglasDistintas)} reglas distintas</td></tr>
        <tr><td style="padding:4px 13px;color:${C.suave}">Destinatarios</td><td style="padding:4px 13px">Analistas del SOC · Administración de sistemas y de red</td></tr>
        <tr><td style="padding:4px 13px;color:${C.suave}">Clasificación</td><td style="padding:4px 13px">Uso interno — Confidencial. Contiene detalle de infraestructura.</td></tr>
      </table>
    </div>

    <div style="display:flex;align-items:center;gap:11px;padding:10px 14px;background:${semColor}0f;border-left:5px solid ${semColor};border-radius:5px;margin:0 0 14px;page-break-inside:avoid">
      <div style="width:14px;height:14px;border-radius:50%;background:${semColor};flex:none"></div>
      <div style="font-size:10.5px;color:${C.texto}"><b style="color:${semColor}">${esc(semTexto.toUpperCase())}</b><br>${a.hallazgos.length} hallazgo(s) en total · ${a.plan.length} acción(es) derivada(s)</div>
    </div>

    <div style="page-break-inside:avoid">
      <h2 style="font-size:14.5px;color:${C.tinta};margin:0 0 10px;padding:0 0 6px;border-bottom:2px solid ${C.marca}">Resumen técnico</h2>
      ${rich(a.resumen, 11)}
    </div>

    <div style="page-break-inside:avoid;margin:16px 0 0;border-top:1px solid ${C.linea};padding-top:9px">
      <b style="font-size:9.5px;color:${C.suave};letter-spacing:.5px">CONTENIDO</b>
      <table style="width:100%;border-collapse:collapse;margin-top:5px">
        ${indice.map((t, i) => `<tr><td style="padding:2px 0;font-size:9.5px;color:${C.texto};width:22px">${i + 1}.</td><td style="padding:2px 0;font-size:9.5px;color:${C.texto}">${esc(t)}</td></tr>`).join('')}
      </table>
    </div>

    <div style="page-break-before:always"></div>

    ${h2(1, 'Alcance y telemetría')}
    ${seccionAlcance(m)}

    ${h2(2, 'Panorama de detecciones')}
    ${seccionPanorama(m)}

    ${h2(3, 'Análisis por dominio')}
    ${seccionDominios(m)}

    ${h2(4, 'Observaciones del analista')}
    ${rich(a.observaciones, 11)}

    ${h2(5, 'Hallazgos priorizados')}
    ${a.hallazgos.length
      ? rich('Cada ficha incluye la evidencia que la sustenta, el impacto técnico, los pasos de remediación, el criterio con el que se dará por cerrada y —cuando aplica— la consulta exacta para reproducir el hallazgo en el Indexer.') +
        a.hallazgos.map((x, i) => fichaHallazgo(x, i + 1)).join('')
      : rich('No se identificaron hallazgos en el periodo analizado. Conviene verificar que la telemetría esté llegando correctamente antes de concluir que la ausencia de hallazgos equivale a ausencia de riesgo.')}

    ${h2(6, 'Plan de acción')}
    ${seccionPlan(m, a)}

    ${h2(7, 'Hoja de ruta por sprints')}
    ${seccionHojaRuta(a)}

    ${h2(8, 'Anexos')}
    ${seccionAnexos(m, a)}
  `;

  return `<!doctype html><html lang="es"><head><meta charset="utf-8"><title>${esc(m.titulo)}</title><style>
    @page { margin: 0; size: A4; }
    * { box-sizing: border-box; }
    body { font-family: 'Liberation Sans', Arial, Helvetica, sans-serif; margin: 0; color: ${C.tinta}; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    h2, h3 { page-break-after: avoid; }
    table { page-break-inside: avoid; }
    .cover { height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center;
             background: linear-gradient(155deg,#101114 0%,#20222a 55%,${C.marcaOsc} 200%); color: #fff; page-break-after: always; padding: 0 40px; }
    .cover img { height: 58px; background: #fff; padding: 6px 9px; border-radius: 8px; margin-bottom: 24px; }
    .content { padding: 24px 30px 44px; }
    .footer-band { position: fixed; bottom: 0; left: 0; right: 0; background: ${C.tinta}; color: #c9cdd4; font-size: 8px;
                   padding: 5px 30px; display: flex; justify-content: space-between; }
  </style></head><body>
    <div class="cover">
      ${logo ? `<img src="${logo}" alt="HexWatch">` : ''}
      <div style="font-size:11px;letter-spacing:4px;color:#f4a58c">HEXWATCH · SOC</div>
      <h1 style="font-size:25px;margin:14px 0 6px;font-weight:700;line-height:1.28">Informe Técnico de<br>Operaciones de Seguridad</h1>
      <div style="width:60px;height:3px;background:${C.marca};margin:12px 0 15px"></div>
      <div style="font-size:15px;color:#e5e7eb">${esc(m.periodo.label)}</div>
      <div style="font-size:10.5px;color:#9aa1ab;margin-top:4px;max-width:520px">${esc(m.periodo.rangoTexto)}</div>
      <div style="margin-top:30px;font-size:11px;color:#b6bcc5">${esc(m.titulo)}</div>
      <div style="margin-top:20px;font-size:9.5px;color:#8b929c">Documento operativo · contiene detalle de infraestructura</div>
      <div style="margin-top:5px;font-size:9.5px;color:#8b929c">Emitido el ${esc(fechaGen)}</div>
    </div>
    <div class="content">${contenido}</div>
    <div class="footer-band">
      <span>Informe Técnico SOC &middot; ${esc(m.periodo.label)}</span>
      <span>HexWatch &middot; Uso interno — Confidencial</span>
    </div>
  </body></html>`;
}
