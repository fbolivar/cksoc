/**
 * MOTOR DE ANALISIS del informe gerencial.
 *
 * Convierte las metricas crudas (exec.data.ts) en:
 *   - hallazgos priorizados, escritos en lenguaje de negocio
 *   - fortalezas del periodo
 *   - narrativa de introduccion, objetivos, resultados, analisis y conclusiones
 *   - recomendaciones, plan de accion y hoja de ruta, todos derivados de los
 *     MISMOS hallazgos para que el documento sea coherente de principio a fin
 *
 * Regla de estilo: nada de jerga. Si un termino tecnico es inevitable, va
 * acompañado de su explicacion entre parentesis.
 */
import type { ReportMetrics } from './exec.data';
import { fechaLarga } from './periodo';

export type Criticidad = 'critica' | 'alta' | 'media' | 'baja';

export interface Hallazgo {
  id: string;
  titulo: string;
  criticidad: Criticidad;
  observacion: string;   // que se observo
  impacto: string;       // que implica para la organizacion
  recomendacion: string; // que se recomienda hacer
  accion: string;        // accion concreta y verificable
  responsable: string;
  plazoDias: number;
  indicador: string;     // como se mide que quedo resuelto
  horizonte: Horizonte;
}

export type Horizonte = 'inmediato' | 'corto' | 'mediano' | 'largo';

export const HORIZONTES: { key: Horizonte; titulo: string; ventana: string; descripcion: string }[] = [
  { key: 'inmediato', titulo: 'Fase 1 — Contención', ventana: '0 a 30 días', descripcion: 'Cerrar las brechas que hoy representan mayor exposición.' },
  { key: 'corto', titulo: 'Fase 2 — Estabilización', ventana: '31 a 90 días', descripcion: 'Normalizar la operación y eliminar las causas de fondo.' },
  { key: 'mediano', titulo: 'Fase 3 — Fortalecimiento', ventana: '91 a 180 días', descripcion: 'Elevar el nivel de protección por encima del mínimo exigido.' },
  { key: 'largo', titulo: 'Fase 4 — Madurez', ventana: '181 a 365 días', descripcion: 'Consolidar la seguridad como una capacidad permanente y medible.' },
];

export interface Fortaleza { titulo: string; detalle: string }

export interface AccionPlan {
  n: number;
  accion: string;
  prioridad: Criticidad;
  responsable: string;
  plazo: string;        // fecha objetivo en texto
  indicador: string;
  origen: string;       // hallazgo del que proviene
}

export interface FaseRuta {
  titulo: string;
  ventana: string;
  descripcion: string;
  iniciativas: string[];
}

export interface Analisis {
  hallazgos: Hallazgo[];
  fortalezas: Fortaleza[];
  introduccion: string;
  objetivos: string[];
  alcance: string;
  resultados: string;
  analisis: string;
  conclusiones: string[];
  recomendaciones: string;
  planAccion: AccionPlan[];
  hojaRuta: FaseRuta[];
}

// --------------------------------------------------------------------------
// Utilidades de redaccion
// --------------------------------------------------------------------------

const fmt = (n: number): string => n.toLocaleString('es-CO');

export const ORDEN_CRITICIDAD: Record<Criticidad, number> = { critica: 0, alta: 1, media: 2, baja: 3 };

export const ETIQUETA_CRITICIDAD: Record<Criticidad, string> = {
  critica: 'Crítica', alta: 'Alta', media: 'Media', baja: 'Baja',
};

/** Redacta la variacion de un indicador frente al periodo anterior. */
function variacionTexto(sustantivo: string, actual: number, previo: number, pct: number | null): string {
  if (previo === 0 && actual === 0) return `${sustantivo} se mantuvo en cero, igual que en el periodo anterior`;
  if (previo === 0) return `${sustantivo} no tiene referencia previa: el periodo anterior no registra datos en la plataforma`;
  if (pct === null) return `${sustantivo} no cuenta con una base de comparación fiable`;
  if (Math.abs(pct) < 5) return `${sustantivo} se mantuvo estable frente al periodo anterior (${pct >= 0 ? '+' : ''}${pct} %)`;
  return pct > 0
    ? `${sustantivo} aumentó un ${pct} % frente al periodo anterior`
    : `${sustantivo} disminuyó un ${Math.abs(pct)} % frente al periodo anterior`;
}

/** Convierte minutos en texto legible ("2 horas 15 minutos"). */
export function duracionTexto(min: number | null): string {
  if (min === null) return 'sin dato';
  if (min < 1) return 'menos de 1 minuto';
  if (min < 60) return `${Math.round(min)} minutos`;
  const h = Math.floor(min / 60);
  const m = Math.round(min % 60);
  if (h < 24) return m ? `${h} h ${m} min` : `${h} horas`;
  const d = Math.floor(h / 24);
  return `${d} día${d === 1 ? '' : 's'} ${h % 24} h`;
}

function fechaObjetivo(desdeIso: string, dias: number): string {
  return fechaLarga(new Date(new Date(desdeIso).getTime() + dias * 86_400_000).toISOString());
}

// --------------------------------------------------------------------------
// Deteccion de hallazgos
// --------------------------------------------------------------------------

const RESP_TI = 'Infraestructura / TI';
const RESP_SEG = 'Coordinación de Seguridad de la Información';
const RESP_SOC = 'Centro de Operaciones de Seguridad (SOC)';
const RESP_DIR = 'Dirección / Gerencia';
const RESP_RRHH = 'Talento Humano con apoyo de Seguridad';

export function detectarHallazgos(m: ReportMetrics): Hallazgo[] {
  const h: Hallazgo[] = [];
  const ps = m.postura;

  // 1) Vulnerabilidades explotadas activamente en el mundo real (CISA KEV)
  if (ps && ps.vulnKev > 0) {
    h.push({
      id: 'kev',
      titulo: 'Fallas de software que los atacantes ya están explotando',
      criticidad: 'critica',
      observacion: `Se identificaron ${fmt(ps.vulnKev)} falla(s) de seguridad en los sistemas de la organización que, según el catálogo oficial de amenazas conocidas de la agencia de ciberseguridad de Estados Unidos (CISA), están siendo aprovechadas activamente por atacantes en este momento.`,
      impacto: 'Son las fallas con mayor probabilidad de ser utilizadas en un ataque real. Su explotación podría derivar en pérdida o secuestro de información, interrupción de los servicios y costos de recuperación no presupuestados.',
      recomendacion: 'Aplicar las actualizaciones correspondientes de forma prioritaria, por encima de cualquier otra tarea de mantenimiento, dentro de una ventana de cambio controlada.',
      accion: 'Actualizar (parchear) el 100 % de los sistemas con fallas de explotación activa conocida.',
      responsable: RESP_TI,
      plazoDias: 15,
      indicador: 'Cero fallas de explotación activa pendientes en el siguiente informe.',
      horizonte: 'inmediato',
    });
  }

  // 2) Vulnerabilidades criticas / altas
  if (ps && (ps.vulnCriticas > 0 || ps.vulnAltas > 0)) {
    const crit = ps.vulnCriticas >= 5 ? 'critica' : ps.vulnCriticas > 0 ? 'alta' : 'media';
    h.push({
      id: 'vuln',
      titulo: 'Actualizaciones de seguridad pendientes en servidores y equipos',
      criticidad: crit as Criticidad,
      observacion: `El análisis de los ${fmt(ps.equiposConVuln)} equipo(s) monitoreados identificó ${ps.vulnTotalAprox ? 'más de ' : ''}${fmt(ps.vulnTotal)} debilidades conocidas de software, de las cuales ${fmt(ps.vulnCriticas)} son de nivel crítico y ${fmt(ps.vulnAltas)} de nivel alto. Son fallas ya documentadas por los fabricantes, para las que en general existe una corrección disponible.`,
      impacto: 'Cada falla sin corregir es una puerta abierta conocida. Un atacante no necesita técnicas sofisticadas: le basta con aprovechar una corrección que la organización aún no ha aplicado.',
      recomendacion: 'Establecer un ciclo formal y periódico de actualizaciones, con ventanas de mantenimiento acordadas con las áreas usuarias y un responsable designado por sistema.',
      accion: 'Definir e implantar un procedimiento mensual de actualizaciones y cerrar las debilidades críticas y altas identificadas.',
      responsable: RESP_TI,
      plazoDias: 45,
      indicador: 'Reducción de al menos el 80 % de las debilidades críticas y altas.',
      horizonte: 'corto',
    });
  }

  // 3) Configuracion segura (hardening CIS)
  if (ps && ps.hardeningScore > 0 && ps.hardeningScore < 80) {
    const peor = ps.hardeningPeor;
    h.push({
      id: 'hardening',
      titulo: 'Configuración de seguridad de los servidores por debajo del estándar',
      criticidad: ps.hardeningScore < 55 ? 'alta' : 'media',
      observacion: `La configuración de los servidores cumple en promedio el ${ps.hardeningScore} % de las buenas prácticas internacionales de configuración segura (estándar CIS).${peor ? ` El equipo con mayor rezago es "${peor.agent}", con un ${peor.score} %.` : ''}`,
      impacto: 'Una configuración débil facilita que un incidente menor se convierta en uno grave, porque el atacante encuentra menos obstáculos para moverse dentro de la red.',
      recomendacion: 'Ejecutar un plan de configuración segura por fases, empezando por los servidores que soportan los servicios más críticos para la operación.',
      accion: 'Elevar el nivel de configuración segura por encima del 80 % en los servidores críticos.',
      responsable: RESP_TI,
      plazoDias: 90,
      indicador: 'Promedio de configuración segura ≥ 80 % en el siguiente informe.',
      horizonte: 'corto',
    });
  }

  // 4) Intentos de acceso no autorizado desde Internet
  if (m.bruteForceIntentos > 0) {
    h.push({
      id: 'accesos',
      titulo: 'Intentos persistentes de acceso no autorizado desde Internet',
      criticidad: m.bruteForceIntentos > 500 ? 'alta' : 'media',
      observacion: `Se registraron ${fmt(m.bruteForceIntentos)} intentos de ingreso con credenciales incorrectas hacia los servicios de acceso remoto, provenientes de ${fmt(m.bruteForceOrigenes)} dirección(es) de Internet distintas. Es un patrón de ataque automatizado: se prueban usuarios y contraseñas hasta acertar.`,
      impacto: 'Si alguna contraseña es débil o se ha reutilizado, un tercero podría ingresar a la red con una identidad legítima, sin que ningún control lo distinga de un empleado.',
      recomendacion: 'Exigir un segundo factor de autenticación (una confirmación adicional en el celular) para todo acceso remoto, y bloquear automáticamente los orígenes reincidentes.',
      accion: 'Habilitar doble factor de autenticación en el 100 % de los accesos remotos y activar el bloqueo automático de orígenes reincidentes.',
      responsable: RESP_TI,
      plazoDias: 60,
      indicador: 'Doble factor activo en todos los usuarios remotos; reducción sostenida de intentos exitosos a cero.',
      horizonte: 'corto',
    });
  }

  // 5) Eventos criticos del periodo
  if (m.criticos > 0) {
    h.push({
      id: 'criticos',
      titulo: 'Eventos de seguridad de máxima severidad detectados',
      criticidad: m.criticos >= 5 ? 'alta' : 'media',
      observacion: `Durante el periodo se detectaron ${fmt(m.criticos)} evento(s) clasificados en el nivel más alto de severidad, que fueron revisados por el equipo de monitoreo.`,
      impacto: 'Estos eventos concentran el mayor riesgo del periodo. Sin un seguimiento documentado, la organización pierde trazabilidad y capacidad de demostrar su gestión ante auditorías.',
      recomendacion: 'Documentar cada evento de máxima severidad como un caso formal, con causa raíz identificada y acción correctiva verificada.',
      accion: 'Cerrar con causa raíz y evidencia el 100 % de los eventos de severidad máxima del periodo.',
      responsable: RESP_SOC,
      plazoDias: 30,
      indicador: 'Todos los eventos críticos con caso documentado y cerrado.',
      horizonte: 'inmediato',
    });
  }

  // 6) Cobertura de monitoreo incompleta
  if (m.agentesTotal > 0 && m.coberturaPct < 100) {
    const fuera = m.agentesTotal - m.agentesActivos;
    h.push({
      id: 'cobertura',
      titulo: 'Equipos sin vigilancia activa',
      criticidad: m.coberturaPct < 80 ? 'alta' : 'media',
      observacion: `${fmt(fuera)} de ${fmt(m.agentesTotal)} equipos registrados no están reportando al sistema de monitoreo (cobertura efectiva del ${m.coberturaPct} %).`,
      impacto: 'Lo que no se vigila no se detecta. Un incidente en esos equipos podría pasar inadvertido durante días o semanas.',
      recomendacion: 'Restablecer el monitoreo en los equipos desconectados y establecer una alerta automática cuando un equipo deje de reportar por más de 24 horas.',
      accion: 'Alcanzar y sostener el 100 % de cobertura de monitoreo sobre el inventario aprobado.',
      responsable: RESP_TI,
      plazoDias: 30,
      indicador: 'Cobertura de monitoreo ≥ 98 % de forma sostenida.',
      horizonte: 'inmediato',
    });
  }

  // 7) Tiempos de atencion / SLA
  if (m.gestion.total > 0 && m.gestion.cumplimientoSlaPct !== null && m.gestion.cumplimientoSlaPct < 90) {
    h.push({
      id: 'sla',
      titulo: 'Tiempos de atención por debajo del compromiso establecido',
      criticidad: m.gestion.cumplimientoSlaPct < 70 ? 'alta' : 'media',
      observacion: `Solo el ${m.gestion.cumplimientoSlaPct} % de los casos del periodo se atendió dentro del tiempo comprometido. El tiempo promedio hasta la primera atención fue de ${duracionTexto(m.gestion.mttaMinutos)}.`,
      impacto: 'Cada hora adicional de demora amplía el alcance de un incidente y el costo de recuperarse de él.',
      recomendacion: 'Revisar la disponibilidad del turno de atención y automatizar el escalamiento cuando un caso supere el tiempo comprometido.',
      accion: 'Alcanzar un cumplimiento de tiempos de atención igual o superior al 90 %.',
      responsable: RESP_SOC,
      plazoDias: 60,
      indicador: 'Cumplimiento de tiempos de atención ≥ 90 % durante dos periodos consecutivos.',
      horizonte: 'corto',
    });
  }

  // 8) Casos abiertos envejecidos
  if ((m.gestion.masAntiguoAbiertoDias ?? 0) > 15) {
    h.push({
      id: 'backlog',
      titulo: 'Casos de seguridad sin cerrar por tiempo prolongado',
      criticidad: (m.gestion.masAntiguoAbiertoDias ?? 0) > 30 ? 'alta' : 'media',
      observacion: `Existen ${fmt(m.gestion.abiertos)} caso(s) abierto(s), el más antiguo con ${m.gestion.masAntiguoAbiertoDias} días sin cierre.`,
      impacto: 'Un caso abierto es un riesgo que sigue vigente. Además distorsiona los indicadores y dificulta priorizar lo verdaderamente urgente.',
      recomendacion: 'Realizar una depuración de casos pendientes y establecer una revisión semanal de vencimientos.',
      accion: 'Depurar el represamiento de casos y no superar 15 días de antigüedad en ningún caso abierto.',
      responsable: RESP_SOC,
      plazoDias: 45,
      indicador: 'Ningún caso abierto con más de 15 días de antigüedad.',
      horizonte: 'corto',
    });
  }

  // 9) Aumento sostenido de la actividad critica
  if (m.variacion.criticos !== null && m.variacion.criticos >= 30 && m.criticos > 0) {
    h.push({
      id: 'tendencia',
      titulo: 'Aumento relevante de la actividad de máxima severidad',
      criticidad: 'media',
      observacion: `Los eventos de máxima severidad crecieron un ${m.variacion.criticos} % respecto al periodo anterior.`,
      impacto: 'Un crecimiento sostenido suele anticipar un cambio en el interés de los atacantes por la organización o una degradación de los controles vigentes.',
      recomendacion: 'Analizar la causa del incremento y ajustar las reglas de detección y los controles perimetrales en consecuencia.',
      accion: 'Ejecutar un análisis de causa del incremento y presentar sus conclusiones en el siguiente comité.',
      responsable: RESP_SEG,
      plazoDias: 30,
      indicador: 'Informe de causa presentado y controles ajustados.',
      horizonte: 'inmediato',
    });
  }

  // 10) Concientizacion (siempre presente como iniciativa estructural)
  h.push({
    id: 'cultura',
    titulo: 'Cultura de seguridad en las personas',
    criticidad: 'baja',
    observacion: 'La mayoría de los incidentes de seguridad en organizaciones similares comienza con una acción cotidiana de un colaborador: abrir un correo fraudulento, reutilizar una contraseña o conectar un dispositivo no autorizado.',
    impacto: 'Sin formación continua, el mejor control tecnológico puede ser anulado por una decisión humana de un segundo.',
    recomendacion: 'Ejecutar un programa continuo de concientización, con simulacros periódicos de correo fraudulento y medición de resultados por área.',
    accion: 'Implementar un programa anual de concientización con al menos un simulacro trimestral.',
    responsable: RESP_RRHH,
    plazoDias: 180,
    indicador: 'Cobertura de formación ≥ 90 % del personal y reducción de la tasa de clic en simulacros.',
    horizonte: 'mediano',
  });

  // 11) Ejercicio de continuidad (madurez)
  h.push({
    id: 'continuidad',
    titulo: 'Preparación ante un incidente mayor',
    criticidad: 'baja',
    observacion: 'La organización cuenta con capacidad de detección y respuesta, pero la efectividad real ante un incidente grave solo se comprueba ejercitándola.',
    impacto: 'Sin ensayo previo, un incidente mayor se enfrenta improvisando, lo que multiplica el tiempo de recuperación y la afectación al servicio.',
    recomendacion: 'Realizar un ejercicio de simulación con la participación de la dirección, y validar la restauración efectiva de las copias de seguridad.',
    accion: 'Ejecutar un ejercicio de simulación de incidente mayor y una prueba de restauración de respaldos.',
    responsable: RESP_DIR,
    plazoDias: 270,
    indicador: 'Ejercicio ejecutado, con acta de lecciones aprendidas y plan de mejora.',
    horizonte: 'largo',
  });

  return h.sort((a, b) => ORDEN_CRITICIDAD[a.criticidad] - ORDEN_CRITICIDAD[b.criticidad]);
}

// --------------------------------------------------------------------------
// Fortalezas del periodo
// --------------------------------------------------------------------------

export function detectarFortalezas(m: ReportMetrics): Fortaleza[] {
  const f: Fortaleza[] = [];
  if (m.agentesActivos > 0) {
    f.push({
      titulo: 'Vigilancia permanente',
      detalle: `Se mantuvo monitoreo ininterrumpido, las 24 horas, sobre ${fmt(m.agentesActivos)} equipo(s) de la organización, con registro y conservación de la evidencia.`,
    });
  }
  if (m.totalEventos > 0) {
    f.push({
      titulo: 'Capacidad de análisis a escala',
      detalle: `Se procesaron y analizaron automáticamente ${fmt(m.totalEventos)} registros de actividad, un volumen imposible de revisar de forma manual, para aislar los pocos que realmente exigían atención.`,
    });
  }
  if (m.ipsBloqueadas.length > 0) {
    f.push({
      titulo: 'Respuesta efectiva',
      detalle: `Se bloquearon ${fmt(m.ipsBloqueadas.length)} origen(es) de actividad maliciosa directamente en el perímetro de la red, con registro de quién, cuándo y por qué.`,
    });
  }
  if (m.gestion.tasaResolucion !== null && m.gestion.tasaResolucion >= 80) {
    f.push({
      titulo: 'Gestión de casos al día',
      detalle: `Se resolvió el ${m.gestion.tasaResolucion} % de los casos abiertos en el periodo${m.gestion.mttrMinutos !== null ? `, con un tiempo promedio de resolución de ${duracionTexto(m.gestion.mttrMinutos)}` : ''}.`,
    });
  }
  if (m.variacion.criticos !== null && m.variacion.criticos < 0) {
    f.push({
      titulo: 'Tendencia favorable',
      detalle: `Los eventos de máxima severidad se redujeron un ${Math.abs(m.variacion.criticos)} % frente al periodo anterior.`,
    });
  }
  if (m.postura?.cumplimiento.some((c) => c.controles > 0)) {
    f.push({
      titulo: 'Evidencia para auditoría',
      detalle: 'La operación genera automáticamente evidencia trazable de controles exigidos por marcos regulatorios reconocidos, lo que reduce el esfuerzo de preparación ante auditorías.',
    });
  }
  return f;
}

// --------------------------------------------------------------------------
// Narrativa
// --------------------------------------------------------------------------

function introduccion(m: ReportMetrics, org: string): string {
  return `El presente documento expone el estado de la seguridad digital de ${org} durante el periodo comprendido ${m.rangoTexto}. Fue elaborado por el Centro de Operaciones de Seguridad y está dirigido a la Dirección y al Comité de Seguridad de la Información, como insumo para la toma de decisiones.

La organización cuenta con una vigilancia permanente sobre sus servidores y equipos: un sistema especializado recoge de forma continua la actividad de la infraestructura tecnológica, la analiza automáticamente y alerta al equipo de seguridad cuando detecta comportamientos que se apartan de lo normal. Este informe traduce esa operación técnica a términos de gestión: qué ocurrió, qué significa para la organización, qué se hizo al respecto y qué decisiones se requieren.

Las cifras que se presentan provienen directamente de los registros del sistema de monitoreo y son verificables. Todo el documento evita el lenguaje técnico; cuando un término especializado resulta inevitable, se acompaña de su explicación.`;
}

function objetivos(): string[] {
  return [
    'Informar a la Dirección, en lenguaje claro y verificable, sobre el estado de la seguridad digital de la organización durante el periodo.',
    'Evidenciar la gestión realizada por el Centro de Operaciones de Seguridad: qué se detectó, qué se atendió y con qué resultado.',
    'Identificar los riesgos vigentes y traducirlos a su posible impacto sobre la operación, la información y la reputación institucional.',
    'Comparar el desempeño con el periodo anterior para determinar si la organización avanza, se mantiene o retrocede.',
    'Proponer un plan de acción priorizado y una hoja de ruta que orienten la asignación de recursos y esfuerzos.',
  ];
}

function alcance(m: ReportMetrics, org: string): string {
  const cob = m.agentesTotal > 0
    ? `El alcance del monitoreo cubre ${fmt(m.agentesTotal)} equipo(s) registrados, de los cuales ${fmt(m.agentesActivos)} reportaron de forma activa durante el periodo (cobertura efectiva del ${m.coberturaPct} %).`
    : 'El alcance del monitoreo corresponde a los equipos registrados en la plataforma de vigilancia.';
  return `${cob} La vigilancia comprende la actividad de los sistemas operativos, los accesos de usuarios, los servicios expuestos a Internet, el estado de actualización de los programas instalados y la configuración de seguridad de los equipos.

Este informe se basa exclusivamente en la información recogida por la plataforma de monitoreo de ${org} en el periodo indicado. Los eventos correspondientes a la operación normal del negocio y los avisos identificados previamente como falsas alarmas se excluyen de los conteos de incidentes, con el fin de no distorsionar el análisis.`;
}

function resultados(m: ReportMetrics): string {
  const bloques: string[] = [];

  bloques.push(
    `Durante el periodo, la plataforma de vigilancia procesó ${fmt(m.totalEventos)} registros de actividad provenientes de la infraestructura tecnológica. Ese volumen corresponde al funcionamiento normal de los sistemas y no representa, en sí mismo, intentos de ataque. Tras el filtrado automático, el sistema clasificó ${fmt(m.criticos)} registro(s) en severidad máxima y ${fmt(m.altos)} en severidad alta; el resto correspondió a actividad rutinaria o a avisos de bajo impacto que no requieren intervención.`
  );

  if (m.gestion.total > 0) {
    const sol = m.gestion.mttrMinutos !== null
      ? ` y el tiempo promedio hasta la solución definitiva, de ${duracionTexto(m.gestion.mttrMinutos)}`
      : '';
    bloques.push(
      `El equipo de seguridad abrió ${fmt(m.gestion.total)} caso(s) formales de atención, de los cuales cerró ${fmt(m.gestion.resueltos)} dentro del periodo (${m.gestion.tasaResolucion ?? 0} %). El tiempo promedio hasta la primera atención fue de ${duracionTexto(m.gestion.mttaMinutos)}${sol}.`
    );
  } else {
    bloques.push(
      'No fue necesario escalar ningún evento a un caso formal de atención durante el periodo: la actividad detectada se resolvió dentro de la operación rutinaria de monitoreo.'
    );
  }

  if (m.bruteForceIntentos > 0) {
    bloques.push(
      `Se registraron ${fmt(m.bruteForceIntentos)} intentos de ingreso con credenciales incorrectas hacia los servicios de acceso remoto, originados en ${fmt(m.bruteForceOrigenes)} dirección(es) de Internet distintas. Ninguno de ellos derivó en un acceso exitoso confirmado.`
    );
  }

  if (m.ipsBloqueadas.length > 0) {
    bloques.push(
      `Como medida de contención se bloquearon ${fmt(m.ipsBloqueadas.length)} origen(es) de Internet en el firewall perimetral (el dispositivo que separa la red interna de Internet), cada uno con su registro de responsable, motivo y fecha.`
    );
  } else {
    bloques.push(
      'No fue necesario aplicar bloqueos en el perímetro de la red: la actividad detectada se mantuvo dentro de niveles gestionables mediante monitoreo.'
    );
  }

  if (m.origenes.length > 0) {
    bloques.push(
      `La actividad sospechosa proveniente de Internet se originó principalmente en ${m.origenes.slice(0, 4).map((o) => o.country).join(', ')}, sobre un total de ${fmt(m.ipsUnicasExternas)} direcciones externas distintas observadas.`
    );
  }

  return bloques.join('\n\n');
}

function analisisNarrativa(m: ReportMetrics): string {
  const b: string[] = [];

  // Comparativo
  if (m.anterior && m.anterior.totalEventos === 0) {
    b.push(
      `**Comparación con el periodo anterior.** El intervalo equivalente anterior (${m.anterior.rangoTexto}) no registra información en la plataforma de vigilancia, por lo que este periodo constituye la **línea base** de medición. A partir del próximo informe será posible evaluar la evolución de los indicadores en el tiempo.`
    );
  } else if (m.anterior) {
    const volTxt = variacionTexto('el volumen de actividad analizada', m.totalEventos, m.anterior.totalEventos, m.variacion.totalEventos);
    const critTxt = variacionTexto('la cifra de eventos de máxima severidad', m.criticos, m.anterior.criticos, m.variacion.criticos);
    b.push(
      `**Comparación con el periodo anterior (${m.anterior.rangoTexto}).** En términos generales, ${volTxt}. En cuanto a lo verdaderamente relevante, ${critTxt}. Estas variaciones deben leerse con cautela: un aumento del volumen total no implica necesariamente mayor riesgo, ya que puede responder a una ampliación de la cobertura de vigilancia o a una mayor sensibilidad de las reglas de detección. Lo relevante para la gestión es la evolución de los eventos de severidad máxima y del tiempo que toma atenderlos.`
    );
  } else {
    b.push(
      '**Línea base.** Este es el primer informe del periodo con datos comparables, por lo que constituye la línea base contra la cual se medirán los periodos siguientes. A partir del próximo informe se incluirá el análisis de evolución.'
    );
  }

  // Naturaleza de la amenaza
  if (m.bruteForceIntentos > 0) {
    b.push(
      '**Naturaleza de la amenaza observada.** El patrón predominante corresponde a intentos automatizados de adivinar usuarios y contraseñas contra los servicios que la organización publica en Internet. No se trata de un ataque dirigido específicamente contra la entidad, sino de una actividad permanente e indiscriminada que afecta a cualquier organización con servicios expuestos. Su relevancia no está en el volumen, sino en que basta con que una sola contraseña sea débil para que uno de esos intentos tenga éxito. Por esa razón, el control más rentable frente a esta amenaza no es tecnológico sino de política: exigir un segundo factor de autenticación.'
    );
  } else {
    b.push(
      '**Naturaleza de la amenaza observada.** No se identificaron campañas de ataque dirigidas contra la organización durante el periodo. La actividad registrada corresponde en su mayoría a exploración automatizada de Internet, un ruido de fondo constante que afecta por igual a cualquier servicio publicado en la red.'
    );
  }

  // Exposicion tecnica traducida
  const ps = m.postura;
  if (ps) {
    const partes: string[] = [];
    if (ps.vulnCriticas + ps.vulnAltas > 0) {
      partes.push(
        `la organización mantiene ${fmt(ps.vulnCriticas + ps.vulnAltas)} debilidades de software de nivel crítico o alto sin corregir${ps.vulnKev > 0 ? `, de las cuales ${fmt(ps.vulnKev)} están siendo explotadas activamente por atacantes en el mundo real` : ''}`
      );
    }
    if (ps.hardeningScore > 0 && ps.hardeningScore < 80) {
      partes.push(`la configuración de seguridad de los servidores alcanza el ${ps.hardeningScore} % del estándar internacional recomendado`);
    }
    if (partes.length) {
      b.push(
        `**Dónde está hoy la exposición real.** Más allá de los intentos de ataque externos, el mayor riesgo del periodo no proviene de lo que ocurrió, sino de lo que sigue pendiente: ${partes.join('; y ')}. Estas condiciones no generan alertas por sí solas, pero determinan qué tan lejos podría llegar un atacante si lograra un primer punto de entrada. Son, por tanto, el foco natural de la inversión del próximo trimestre.`
      );
    } else {
      b.push(
        '**Dónde está hoy la exposición real.** Los sistemas evaluados no presentan debilidades de software críticas pendientes ni desviaciones relevantes de configuración segura. La exposición actual de la organización se considera baja y bajo control.'
      );
    }
  }

  // Capacidad de respuesta
  if (m.gestion.total > 0) {
    const cumple = m.gestion.cumplimientoSlaPct;
    b.push(
      `**Capacidad de respuesta.** El indicador determinante no es cuántos eventos ocurrieron, sino cuánto tarda la organización en reaccionar. En este periodo, la primera atención tomó en promedio ${duracionTexto(m.gestion.mttaMinutos)}${m.gestion.mttrMinutos !== null ? ` y la solución definitiva ${duracionTexto(m.gestion.mttrMinutos)}` : ''}${cumple !== null ? `, con un cumplimiento del ${cumple} % de los tiempos comprometidos` : ''}. ${cumple !== null && cumple >= 90 ? 'El desempeño se encuentra dentro de lo esperado.' : 'Existe margen de mejora: cada hora de demora amplía el alcance potencial de un incidente y encarece su recuperación.'}`
    );
  }

  // Cobertura
  if (m.agentesTotal > 0 && m.coberturaPct < 100) {
    b.push(
      `**Puntos ciegos.** ${fmt(m.agentesTotal - m.agentesActivos)} equipo(s) no reportaron al sistema de vigilancia durante el periodo. Sobre ellos, la organización no tiene visibilidad: un incidente allí no generaría alerta alguna. Restablecer esa cobertura es una acción de bajo costo y alto retorno.`
    );
  }

  return b.join('\n\n');
}

function conclusiones(m: ReportMetrics, hs: Hallazgo[]): string[] {
  const c: string[] = [];
  const criticos = hs.filter((h) => h.criticidad === 'critica').length;
  const altos = hs.filter((h) => h.criticidad === 'alta').length;

  if (m.semaforo === 'rojo') {
    c.push('La postura de seguridad del periodo requiere atención de la Dirección: existen condiciones de riesgo que superan el nivel aceptable y deben resolverse en el corto plazo.');
  } else if (m.semaforo === 'amarillo') {
    c.push('La postura de seguridad del periodo es estable y se encuentra bajo gestión activa: se detectaron y atendieron situaciones de riesgo sin afectación a la operación.');
  } else {
    c.push('La postura de seguridad del periodo fue satisfactoria: no se identificaron situaciones que comprometieran la operación de la organización.');
  }

  c.push(`No se registró interrupción de servicios ni pérdida de información atribuible a un incidente de seguridad durante el periodo${m.ipsBloqueadas.length ? `; las amenazas identificadas fueron contenidas mediante ${fmt(m.ipsBloqueadas.length)} bloqueo(s) en el perímetro` : ''}.`);

  if (criticos + altos > 0) {
    c.push(`Se identificaron ${criticos + altos} situación(es) de prioridad ${criticos > 0 ? 'crítica y alta' : 'alta'} que exigen decisión y asignación de recursos; se detallan en el plan de acción de este informe.`);
  } else {
    c.push('No se identificaron situaciones de prioridad crítica o alta pendientes; las recomendaciones del informe apuntan a consolidar y elevar el nivel de madurez alcanzado.');
  }

  c.push('La inversión sostenida en vigilancia continua está entregando resultados medibles: la organización detecta, documenta y responde, y cuenta con evidencia trazable para efectos de auditoría y cumplimiento.');

  if (m.gestion.cumplimientoSlaPct !== null && m.gestion.cumplimientoSlaPct < 90) {
    c.push('El principal margen de mejora del periodo está en los tiempos de atención, no en la capacidad de detección.');
  }

  return c;
}

// --------------------------------------------------------------------------
// Recomendaciones, plan de accion y hoja de ruta
// --------------------------------------------------------------------------

export function construirRecomendaciones(hs: Hallazgo[]): string {
  return hs
    .slice(0, 8)
    .map((h, i) => `${i + 1}. [${ETIQUETA_CRITICIDAD[h.criticidad]}] ${h.recomendacion}`)
    .join('\n');
}

export function construirPlanAccion(m: ReportMetrics, hs: Hallazgo[]): AccionPlan[] {
  return hs.map((h, i) => ({
    n: i + 1,
    accion: h.accion,
    prioridad: h.criticidad,
    responsable: h.responsable,
    plazo: fechaObjetivo(m.generadoEn, h.plazoDias),
    indicador: h.indicador,
    origen: h.titulo,
  }));
}

export function construirHojaRuta(hs: Hallazgo[]): FaseRuta[] {
  return HORIZONTES.map((h) => ({
    titulo: h.titulo,
    ventana: h.ventana,
    descripcion: h.descripcion,
    iniciativas: hs.filter((x) => x.horizonte === h.key).map((x) => x.accion),
  })).filter((f) => f.iniciativas.length > 0);
}

// --------------------------------------------------------------------------
// Entrada principal
// --------------------------------------------------------------------------

export function analizar(m: ReportMetrics, org = 'la organización'): Analisis {
  const hallazgos = detectarHallazgos(m);
  return {
    hallazgos,
    fortalezas: detectarFortalezas(m),
    introduccion: introduccion(m, org),
    objetivos: objetivos(),
    alcance: alcance(m, org),
    resultados: resultados(m),
    analisis: analisisNarrativa(m),
    conclusiones: conclusiones(m, hallazgos),
    recomendaciones: construirRecomendaciones(hallazgos),
    planAccion: construirPlanAccion(m, hallazgos),
    hojaRuta: construirHojaRuta(hallazgos),
  };
}
