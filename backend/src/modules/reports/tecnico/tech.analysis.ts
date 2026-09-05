/**
 * MOTOR DE ANALISIS TECNICO del SOC.
 *
 * Convierte la telemetria (tech.data.ts) en hallazgos accionables. Cada
 * hallazgo lleva:
 *   - evidencia concreta (regla, host, IP, usuario, CVE)
 *   - la CONSULTA para reproducirlo en el Indexer
 *   - pasos de remediacion ejecutables
 *   - responsable, esfuerzo, plazo y criterio de aceptacion
 *
 * De esa misma lista salen las recomendaciones, el plan de accion y la hoja de
 * ruta, de modo que el informe sea coherente y verificable de punta a punta.
 */
import type { TechMetrics } from './tech.data';
import { fechaLarga } from '../executive/periodo';

export type SevTecnica = 'critica' | 'alta' | 'media' | 'baja' | 'info';
export type Confianza = 'alta' | 'media' | 'baja';
export type Sprint = 's1' | 's2' | 's3' | 'continuo';

export type Dominio =
  | 'deteccion' | 'accesos' | 'exposicion' | 'vulnerabilidades'
  | 'hardening' | 'integridad' | 'telemetria' | 'operacion' | 'inteligencia';

export const DOMINIOS: Record<Dominio, string> = {
  deteccion: 'Ingeniería de detección',
  accesos: 'Accesos y autenticación',
  exposicion: 'Exposición y perímetro',
  vulnerabilidades: 'Gestión de vulnerabilidades',
  hardening: 'Configuración segura',
  integridad: 'Integridad de archivos',
  telemetria: 'Telemetría y cobertura',
  operacion: 'Operación del SOC',
  inteligencia: 'Inteligencia de amenazas',
};

export const SPRINTS: { key: Sprint; titulo: string; ventana: string; objetivo: string }[] = [
  { key: 's1', titulo: 'Sprint 1 — Contención y triage', ventana: 'Semanas 1–2', objetivo: 'Cerrar lo explotable hoy y recuperar la visibilidad perdida.' },
  { key: 's2', titulo: 'Sprint 2 — Reducción de superficie', ventana: 'Semanas 3–6', objetivo: 'Parcheo, endurecimiento y afinamiento de reglas.' },
  { key: 's3', titulo: 'Sprint 3 — Cobertura de detección', ventana: 'Semanas 7–12', objetivo: 'Cubrir puntos ciegos de ATT&CK y automatizar respuesta.' },
  { key: 'continuo', titulo: 'Operación continua', ventana: 'Permanente', objetivo: 'Rutinas que deben quedar instaladas en la operación diaria.' },
];

export interface HallazgoTecnico {
  id: string;
  dominio: Dominio;
  titulo: string;
  severidad: SevTecnica;
  confianza: Confianza;
  evidencia: string;
  detalle: string[];
  impacto: string;
  consulta: string | null;
  remediacion: string[];
  responsable: string;
  esfuerzo: string;
  plazoDias: number;
  aceptacion: string;
  sprint: Sprint;
}

export interface AccionTecnica {
  n: number;
  accion: string;
  dominio: Dominio;
  severidad: SevTecnica;
  responsable: string;
  esfuerzo: string;
  plazo: string;
  aceptacion: string;
  origen: string;
}

export interface FaseTecnica {
  titulo: string;
  ventana: string;
  objetivo: string;
  items: { accion: string; dominio: string; severidad: SevTecnica }[];
  esfuerzoTotal: string;
}

export interface AnalisisTecnico {
  hallazgos: HallazgoTecnico[];
  resumen: string;
  observaciones: string;
  plan: AccionTecnica[];
  hojaRuta: FaseTecnica[];
  iocs: { tipo: string; valor: string; contexto: string }[];
}

// --------------------------------------------------------------------------
// Utilidades
// --------------------------------------------------------------------------

const fmt = (n: number): string => n.toLocaleString('es-CO');

export const ORDEN_SEV: Record<SevTecnica, number> = { critica: 0, alta: 1, media: 2, baja: 3, info: 4 };
export const ETIQUETA_SEV: Record<SevTecnica, string> = {
  critica: 'Crítica', alta: 'Alta', media: 'Media', baja: 'Baja', info: 'Informativa',
};

const RESP_SOC = 'Analista SOC';
const RESP_DET = 'Ingeniería de detección';
const RESP_SYS = 'Administración de sistemas';
const RESP_RED = 'Administración de red / firewall';
const RESP_IAM = 'Administración de identidades';

/** Consulta DSL lista para pegar en el Indexer. */
function dsl(indice: string, filtros: unknown[], extra: Record<string, unknown> = {}): string {
  const body = { query: { bool: { filter: filtros } }, ...extra };
  return `GET ${indice}/_search\n${JSON.stringify(body, null, 2)}`;
}

function ventana(m: TechMetrics) {
  return { range: { timestamp: { gte: m.periodo.gte, lt: m.periodo.lt } } };
}

const IDX = 'wazuh-alerts-*';

/** Puertos que rara vez deberían estar expuestos sin control. */
const PUERTOS_SENSIBLES: Record<number, string> = {
  21: 'FTP (credenciales en claro)',
  23: 'Telnet (credenciales en claro)',
  445: 'SMB',
  3306: 'MySQL',
  3389: 'RDP',
  5432: 'PostgreSQL',
  5900: 'VNC',
  6379: 'Redis',
  9200: 'Elasticsearch/OpenSearch',
  27017: 'MongoDB',
  11211: 'Memcached',
};

function esExpuesto(ip: string): boolean {
  return ip === '0.0.0.0' || ip === '::' || ip === '*';
}

// --------------------------------------------------------------------------
// Deteccion de hallazgos
// --------------------------------------------------------------------------

export function detectarHallazgos(m: TechMetrics): HallazgoTecnico[] {
  const h: HallazgoTecnico[] = [];

  // ---------------- Ingeniería de detección ----------------

  const ruidosa = m.topReglas[0];
  if (ruidosa && ruidosa.pctVolumen >= 20) {
    h.push({
      id: 'det-ruido',
      dominio: 'deteccion',
      titulo: `La regla ${ruidosa.ruleId} concentra el ${ruidosa.pctVolumen} % de todo el volumen`,
      severidad: ruidosa.pctVolumen >= 40 ? 'alta' : 'media',
      confianza: 'alta',
      evidencia: `«${ruidosa.descripcion}» (nivel ${ruidosa.nivel}) generó ${fmt(ruidosa.conteo)} eventos sobre ${fmt(m.total)} del periodo, en ${ruidosa.agentes} agente(s).`,
      detalle: m.topReglas.slice(0, 5).map((r) => `${r.ruleId} · nivel ${r.nivel} · ${fmt(r.conteo)} eventos (${r.pctVolumen} %) · ${r.descripcion}`),
      impacto: 'Una sola regla dominando el volumen degrada la relación señal/ruido, encarece el almacenamiento y entrena al equipo a ignorar alertas. Además distorsiona cualquier métrica basada en conteo bruto.',
      consulta: dsl(IDX, [ventana(m), { term: { 'rule.id': ruidosa.ruleId } }], {
        size: 0,
        aggs: { agentes: { terms: { field: 'agent.name', size: 10 } }, campos: { terms: { field: 'data.srcip', size: 10 } } },
      }),
      remediacion: [
        `Revisar en Detección → Reglas ruidosas el detalle de la regla ${ruidosa.ruleId} y determinar si el patrón es legítimo.`,
        'Si es actividad normal y acotada, crear una supresión por el campo discriminante (host, usuario o IP) en lugar de silenciar la regla completa.',
        `Si el ruido es estructural, ajustar el nivel o el ámbito en local_rules.xml sobrescribiendo la regla ${ruidosa.ruleId} (usar <rule id="..." level="..." overwrite="yes">).`,
        'Documentar el ajuste y su justificación, y añadir el ID a REPORT_EXCLUDE_RULES solo si debe quedar fuera de los conteos de incidentes.',
      ],
      responsable: RESP_DET,
      esfuerzo: '2–4 h',
      plazoDias: 14,
      aceptacion: 'Ninguna regla supera el 20 % del volumen total en el siguiente informe.',
      sprint: 's2',
    });
  }

  const criticasRuidosas = m.topReglas.filter((r) => r.nivel >= 12 && r.conteo >= 50);
  if (criticasRuidosas.length > 0) {
    h.push({
      id: 'det-crit-volumen',
      dominio: 'deteccion',
      titulo: 'Reglas de severidad crítica disparando en volumen alto',
      severidad: 'alta',
      confianza: 'media',
      evidencia: `${criticasRuidosas.length} regla(s) de nivel ≥ 12 superan los 50 eventos en el periodo. Un nivel crítico debería ser excepcional: o hay un incidente real sin caso abierto, o la clasificación de la regla no corresponde.`,
      detalle: criticasRuidosas.slice(0, 6).map((r) => `${r.ruleId} · nivel ${r.nivel} · ${fmt(r.conteo)} eventos · ${r.descripcion}`),
      impacto: 'Si son falsos positivos, contaminan el indicador de eventos críticos que se reporta a dirección. Si son reales, hay actividad maliciosa sostenida que no se está gestionando como incidente.',
      consulta: dsl(IDX, [ventana(m), { range: { 'rule.level': { gte: 12 } } }], {
        size: 0,
        aggs: { reglas: { terms: { field: 'rule.id', size: 20 }, aggs: { agentes: { terms: { field: 'agent.name', size: 5 } } } } },
      }),
      remediacion: [
        'Tomar una muestra de cada regla y validar manualmente si el evento corresponde a actividad maliciosa.',
        'Para los falsos positivos: reclasificar el nivel en local_rules.xml o crear la supresión correspondiente.',
        'Para los verdaderos positivos: abrir caso en Incidentes, asignar responsable y documentar la contención aplicada.',
      ],
      responsable: RESP_SOC,
      esfuerzo: '4 h',
      plazoDias: 7,
      aceptacion: 'Cada regla crítica de alto volumen queda clasificada como incidente gestionado o como falso positivo documentado.',
      sprint: 's1',
    });
  }

  const ciegas = m.cobertura?.tactics.filter((t) => t.detected === 0) ?? [];
  if (ciegas.length > 0) {
    h.push({
      id: 'det-cobertura',
      dominio: 'deteccion',
      titulo: `${ciegas.length} táctica(s) de MITRE ATT&CK sin una sola detección`,
      severidad: ciegas.length >= 6 ? 'alta' : 'media',
      confianza: 'alta',
      evidencia: `De ${m.cobertura?.tacticsTotal ?? 0} tácticas del marco, ${m.cobertura?.tacticsCovered ?? 0} registraron detecciones y ${ciegas.length} ninguna. Técnicas distintas observadas: ${m.cobertura?.techniquesDetected ?? 0}.`,
      detalle: ciegas.slice(0, 10).map((t) => `${t.tactic} — 0 de ${t.total} técnicas del marco con detección`),
      impacto: 'Un adversario que opere dentro de esas tácticas no generará ninguna alerta. Los puntos ciegos no se manifiestan como fallos: se manifiestan como silencio.',
      consulta: dsl(IDX, [ventana(m), { exists: { field: 'rule.mitre.tactic' } }], {
        size: 0,
        aggs: { tacticas: { terms: { field: 'rule.mitre.tactic', size: 20 }, aggs: { tecnicas: { cardinality: { field: 'rule.mitre.id' } } } } },
      }),
      remediacion: [
        'Priorizar las tácticas ciegas según lo que sea plausible en esta infraestructura (no todas aplican).',
        'Verificar primero si falta la fuente de datos (auditoría de procesos, logs de PowerShell, Sysmon, netflow) antes de escribir reglas.',
        'Activar los decoders/módulos de Wazuh que cubran esas fuentes y validar que llegan eventos.',
        'Escribir reglas propias en local_rules.xml para las técnicas prioritarias y probarlas con logs simulados.',
      ],
      responsable: RESP_DET,
      esfuerzo: '1–2 semanas',
      plazoDias: 90,
      aceptacion: 'Reducir al menos a la mitad el número de tácticas sin detección.',
      sprint: 's3',
    });
  }

  if (m.reglasPropias.length < 5) {
    h.push({
      id: 'det-reglas-propias',
      dominio: 'deteccion',
      titulo: 'Detección basada casi exclusivamente en el ruleset por defecto',
      severidad: 'media',
      confianza: 'alta',
      evidencia: `Solo hay ${m.reglasPropias.length} regla(s) propia(s) cargada(s) en local_rules.xml.`,
      detalle: m.reglasPropias.slice(0, 6).map((r) => `${r.id} · nivel ${r.level} · ${r.description}`),
      impacto: 'El ruleset genérico no conoce los activos críticos, las cuentas de servicio ni los flujos legítimos de esta organización. Sin reglas propias no hay detección de abuso específico del negocio.',
      consulta: null,
      remediacion: [
        'Identificar los 5 escenarios de mayor riesgo propios de la organización (acceso a datos sensibles, uso de cuentas privilegiadas, cambios en producción fuera de ventana).',
        'Escribir una regla por escenario en local_rules.xml, con nivel acorde y grupo propio para poder medirlas.',
        'Validar cada regla con `wazuh-logtest` antes de aplicarla.',
      ],
      responsable: RESP_DET,
      esfuerzo: '1 semana',
      plazoDias: 60,
      aceptacion: 'Al menos 5 reglas propias activas y disparando correctamente.',
      sprint: 's3',
    });
  }

  // ---------------- Accesos y autenticación ----------------

  if (m.auth.fallos > 50 && (m.auth.ratioFallo ?? 0) >= 40) {
    const ipsPub = m.auth.ipsOrigen.filter((i) => i.publica);
    h.push({
      id: 'auth-fuerza-bruta',
      dominio: 'accesos',
      titulo: 'Patrón sostenido de fallos de autenticación',
      severidad: ipsPub.length > 0 ? 'alta' : 'media',
      confianza: 'alta',
      evidencia: `${fmt(m.auth.fallos)} fallos frente a ${fmt(m.auth.exitos)} autenticaciones exitosas (${m.auth.ratioFallo} % de fallo). ${ipsPub.length} de las IP origen son públicas.`,
      detalle: [
        ...m.auth.usuariosAtacados.slice(0, 5).map((u) => `Usuario objetivo: ${u.usuario} — ${fmt(u.fallos)} fallos`),
        ...ipsPub.slice(0, 5).map((i) => `Origen público: ${i.ip}${i.pais ? ` (${i.pais})` : ''} — ${fmt(i.fallos)} fallos`),
      ],
      impacto: 'Un ratio de fallo por encima del 40 % con orígenes públicos indica fuerza bruta o password spraying activo. Basta una contraseña débil o reutilizada para convertirlo en un acceso legítimo no autorizado.',
      consulta: dsl(IDX, [ventana(m), { terms: { 'rule.groups': ['authentication_failed', 'win_authentication_failed'] } }], {
        size: 0,
        aggs: {
          por_ip: { terms: { field: 'data.srcip', size: 20 }, aggs: { usuarios: { terms: { field: 'data.srcuser', size: 5 } } } },
        },
      }),
      remediacion: [
        'Bloquear en el firewall perimetral las IP públicas reincidentes (módulo Respuesta → Bloquear IP).',
        'Exigir segundo factor (MFA) en todos los accesos remotos y en las cuentas administrativas.',
        'Verificar que las cuentas objetivo existan realmente; si son cuentas genéricas o de prueba, deshabilitarlas.',
        'Activar bloqueo temporal por intentos fallidos (active response de Wazuh o política del propio servicio).',
        'Revisar si alguna de las cuentas atacadas registró también una autenticación exitosa en la ventana.',
      ],
      responsable: RESP_IAM,
      esfuerzo: '4–8 h',
      plazoDias: 7,
      aceptacion: 'Ratio de fallo por debajo del 20 % y MFA activo en el 100 % de accesos remotos.',
      sprint: 's1',
    });
  }

  // Cuentas que aparecen tanto en fallos como en exitos: verificar
  const atacados = new Set(m.auth.usuariosAtacados.map((u) => u.usuario.toLowerCase()));
  const sospechosos = m.auth.usuariosConExito.filter((u) => atacados.has(u.usuario.toLowerCase()));
  if (sospechosos.length > 0 && m.auth.fallos > 20) {
    h.push({
      id: 'auth-exito-tras-fallos',
      dominio: 'accesos',
      titulo: 'Cuentas con fallos repetidos que además registran accesos exitosos',
      severidad: 'alta',
      confianza: 'media',
      evidencia: `${sospechosos.length} cuenta(s) aparecen simultáneamente entre las más atacadas y entre las que autenticaron con éxito en la misma ventana.`,
      detalle: sospechosos.slice(0, 6).map((u) => `${u.usuario} — ${fmt(u.exitos)} accesos exitosos; también entre las cuentas con más fallos`),
      impacto: 'Es el patrón esperado tanto de un usuario que se equivoca de contraseña como de un ataque exitoso. La diferencia solo se establece revisando el origen y la hora del acceso exitoso, y esa verificación no puede omitirse.',
      consulta: dsl(IDX, [ventana(m), { terms: { 'rule.groups': ['authentication_success'] } }], {
        size: 50,
        _source: ['timestamp', 'agent.name', 'data.dstuser', 'data.srcip', 'rule.description'],
        sort: [{ timestamp: 'desc' }],
      }),
      remediacion: [
        'Para cada cuenta, comparar el origen y la franja horaria del acceso exitoso con su comportamiento habitual (módulo UEBA → perfil de entidad).',
        'Si el origen es público o inusual, forzar cambio de contraseña, revocar sesiones activas y abrir caso.',
        'Documentar el resultado de la verificación aunque sea negativo: es la evidencia de que se revisó.',
      ],
      responsable: RESP_SOC,
      esfuerzo: '2 h por cuenta',
      plazoDias: 3,
      aceptacion: 'Todas las cuentas verificadas y documentadas; las comprometidas con credenciales rotadas.',
      sprint: 's1',
    });
  }

  const anomAbiertas = m.anomalias.filter((a) => a.estado === 'open');
  if (anomAbiertas.length > 0) {
    h.push({
      id: 'auth-ueba',
      dominio: 'accesos',
      titulo: `${anomAbiertas.length} anomalía(s) de comportamiento sin revisar`,
      severidad: anomAbiertas.some((a) => a.severidad === 'critica' || a.severidad === 'alta') ? 'alta' : 'media',
      confianza: 'media',
      evidencia: `El motor de comportamiento (UEBA) marcó ${anomAbiertas.length} desviación(es) respecto a la línea base de los usuarios y siguen en estado abierto.`,
      detalle: anomAbiertas.slice(0, 8).map((a) => `[${a.detector}] ${a.entidad} — ${a.titulo} (score ${a.score}, ${a.severidad})`),
      impacto: 'Las anomalías de comportamiento detectan lo que las reglas no: uso legítimo de credenciales robadas. Sin triage, la detección existe pero no produce ningún efecto.',
      consulta: null,
      remediacion: [
        'Revisar cada anomalía en UEBA → Anomalías y marcarla como reconocida o descartada, con comentario.',
        'Para viajes imposibles y países nuevos, confirmar con el usuario por un canal fuera de banda.',
        'Si la desviación se explica por un cambio legítimo (nuevo cargo, nueva sede), actualizar la línea base.',
      ],
      responsable: RESP_SOC,
      esfuerzo: '15 min por anomalía',
      plazoDias: 7,
      aceptacion: 'Cero anomalías en estado abierto con más de 7 días de antigüedad.',
      sprint: 's1',
    });
  }

  // ---------------- Exposición y perímetro ----------------

  const ipsRelevantes = m.ipsExternas.filter((i) => i.nivelMax >= 10 || i.reglasDistintas >= 3);
  if (ipsRelevantes.length > 0) {
    h.push({
      id: 'exp-ips',
      dominio: 'exposicion',
      titulo: `${ipsRelevantes.length} dirección(es) externa(s) con actividad relevante`,
      severidad: ipsRelevantes.some((i) => i.nivelMax >= 12) ? 'alta' : 'media',
      confianza: 'alta',
      evidencia: 'Direcciones públicas que dispararon reglas de nivel alto o tocaron varias reglas distintas (indicador de exploración o intento dirigido).',
      detalle: ipsRelevantes.slice(0, 8).map((i) =>
        `${i.ip}${i.pais ? ` (${i.pais})` : ''} — ${fmt(i.conteo)} eventos, nivel máx ${i.nivelMax}, ${i.reglasDistintas} reglas distintas, agentes: ${i.agentes.join(', ') || 'n/d'}`
      ),
      impacto: 'Una IP que activa varias reglas distintas no está haciendo ruido de fondo: está probando superficies diferentes. Es el precursor habitual de un intento dirigido.',
      consulta: dsl(IDX, [ventana(m), { terms: { 'data.srcip': ipsRelevantes.slice(0, 5).map((i) => i.ip) } }], {
        size: 100,
        _source: ['timestamp', 'agent.name', 'rule.id', 'rule.level', 'rule.description', 'data.srcip'],
        sort: [{ timestamp: 'asc' }],
      }),
      remediacion: [
        'Consultar la reputación de cada IP (módulo Threat Intel) antes de decidir el bloqueo.',
        'Bloquear en el firewall perimetral las que tengan reputación negativa o actividad sostenida (Respuesta → Bloquear IP, queda auditado).',
        'Para las IP que tocaron varios agentes, revisar si existe un patrón de movimiento lateral o de escaneo interno.',
        'Añadir las confirmadas como maliciosas al listado de IOC para correlación futura.',
      ],
      responsable: RESP_RED,
      esfuerzo: '3 h',
      plazoDias: 7,
      aceptacion: 'Todas las IP evaluadas; las maliciosas bloqueadas y registradas como IOC.',
      sprint: 's1',
    });
  }

  if (m.iocMatches.length > 0) {
    const porIp = m.iocMatches.filter((i) => i.type === 'ip');
    const otros = m.iocMatches.filter((i) => i.type !== 'ip');
    // Las coincidencias por dominio contra feeds de URL producen falsos
    // positivos frecuentes (CDN y almacenamiento en la nube usados de forma
    // puntual para alojar contenido malicioso). Solo las de IP se tratan como
    // criticas de entrada; el resto exige descarte previo.
    h.push({
      id: 'exp-ioc',
      dominio: 'inteligencia',
      titulo: `${m.iocMatches.length} coincidencia(s) con indicadores de compromiso conocidos`,
      severidad: porIp.length > 0 ? 'critica' : 'alta',
      confianza: porIp.length > 0 ? 'alta' : 'media',
      evidencia: `Se observó actividad que coincide con indicadores de las fuentes de inteligencia cargadas: ${porIp.length} por dirección IP y ${otros.length} por dominio o URL.`,
      detalle: m.iocMatches.slice(0, 8).map((i) =>
        `${i.type}: ${i.value} — fuente ${i.source}, ${fmt(i.alertCount)} alerta(s), agente ${i.agent || 'n/d'}, últ. ${i.lastSeen}`
      ),
      impacto: `Una coincidencia con un IOC conocido es la señal de mayor valor disponible: el indicador ya fue asociado a actividad maliciosa por un tercero.${
        otros.length > 0
          ? ' No obstante, las coincidencias por dominio contra fuentes de URL generan falsos positivos con frecuencia: los servicios legítimos de CDN y almacenamiento en la nube aparecen en esos catálogos porque alguien alojó allí contenido malicioso puntual. El dominio por sí solo no incrimina; la URL completa sí.'
          : ''
      }`,
      consulta: porIp.length > 0
        ? dsl(IDX, [ventana(m), { terms: { 'data.srcip': porIp.slice(0, 8).map((i) => i.value) } }], {
            size: 50,
            _source: ['timestamp', 'agent.name', 'rule.description', 'data.srcip', 'data.url'],
            sort: [{ timestamp: 'desc' }],
          })
        : dsl(IDX, [ventana(m), { query_string: { query: otros.slice(0, 6).map((i) => `"${i.value}"`).join(' OR ') } }], {
            size: 50,
            _source: ['timestamp', 'agent.name', 'rule.description', 'data.url', 'data.dstip'],
            sort: [{ timestamp: 'desc' }],
          }),
      remediacion: [
        ...(otros.length > 0
          ? ['Descartar primero los falsos positivos: revisar la URL completa del evento, no solo el dominio. Un dominio de CDN o de almacenamiento en la nube reputado no constituye por sí mismo un indicador de compromiso.']
          : []),
        'Aislar preventivamente el host implicado si la coincidencia es de alta confianza (Velociraptor → aislamiento de endpoint).',
        'Bloquear el indicador en el perímetro cuando quede confirmado.',
        'Ejecutar búsqueda retrospectiva del indicador en toda la telemetría disponible, no solo en la ventana del informe.',
        'Abrir caso con la evidencia y la línea de tiempo completa.',
        ...(otros.length > 0
          ? ['Si el falso positivo es recurrente, añadir el dominio a la lista blanca de la fuente para no volver a gastar triage en él.']
          : []),
      ],
      responsable: RESP_SOC,
      esfuerzo: '4 h',
      plazoDias: porIp.length > 0 ? 1 : 3,
      aceptacion: 'Cada coincidencia verificada: contenida y documentada en un caso, o descartada como falso positivo con su justificación.',
      sprint: 's1',
    });
  }

  const expuestos = m.puertos.filter((p) => PUERTOS_SENSIBLES[p.port] && esExpuesto(p.ip));
  if (expuestos.length > 0) {
    h.push({
      id: 'exp-puertos',
      dominio: 'exposicion',
      titulo: `${expuestos.length} servicio(s) sensible(s) escuchando en todas las interfaces`,
      severidad: expuestos.some((p) => [23, 21, 3389].includes(p.port)) ? 'alta' : 'media',
      confianza: 'alta',
      evidencia: 'Servicios con puerto sensible enlazados a 0.0.0.0, es decir, accesibles desde cualquier red que alcance al host.',
      detalle: expuestos.slice(0, 10).map((p) => `${p.agent} — puerto ${p.port}/${p.transport} (${PUERTOS_SENSIBLES[p.port]}) — proceso ${p.process || 'n/d'}`),
      impacto: 'Cada servicio enlazado a todas las interfaces amplía la superficie de ataque sin necesidad. Los protocolos en claro (FTP, Telnet) además exponen credenciales a cualquiera con acceso al segmento.',
      consulta: null,
      remediacion: [
        'Para cada servicio, determinar si realmente necesita escuchar en todas las interfaces o basta con 127.0.0.1 o la IP de gestión.',
        'Reconfigurar el bind del servicio y reiniciarlo en ventana de mantenimiento.',
        'Si el servicio debe seguir expuesto, restringir por firewall local (nftables/iptables) al origen estrictamente necesario.',
        'Sustituir los protocolos en claro (Telnet → SSH, FTP → SFTP) donde aparezcan.',
      ],
      responsable: RESP_SYS,
      esfuerzo: '1 día',
      plazoDias: 30,
      aceptacion: 'Ningún servicio sensible enlazado a 0.0.0.0 sin justificación documentada.',
      sprint: 's2',
    });
  }

  // ---------------- Vulnerabilidades ----------------

  const v = m.vuln;
  if (v && v.resumen.kev > 0) {
    const kev = (v.priorizadas ?? []).filter((c) => (c as { inKev?: boolean }).inKev).slice(0, 8);
    h.push({
      id: 'vul-kev',
      dominio: 'vulnerabilidades',
      titulo: `${fmt(v.resumen.kev)} vulnerabilidad(es) con explotación activa confirmada (CISA KEV)`,
      severidad: 'critica',
      confianza: 'alta',
      evidencia: `Del total detectado, ${fmt(v.resumen.kev)} figuran en el catálogo KEV de CISA: existe explotación observada en el mundo real, no teórica.`,
      detalle: (kev.length ? kev : (v.topCve ?? []).filter((c) => c.inKev).slice(0, 8))
        .map((c) => {
          const x = c as { cve: string; severity?: string; score?: number | null; epss?: number | null };
          return `${x.cve} — severidad ${x.severity ?? 'n/d'}${x.score ? `, CVSS ${x.score}` : ''}${x.epss != null ? `, EPSS ${(x.epss * 100).toFixed(1)} %` : ''}`;
        }),
      impacto: 'Son las vulnerabilidades con mayor probabilidad de ser explotadas: hay exploit público y campañas activas. El tiempo de exposición es el único factor que la organización todavía controla.',
      consulta: null,
      remediacion: [
        'Identificar los hosts afectados en Vulnerabilidades → priorizadas, filtrando por KEV.',
        'Abrir ventana de cambio de emergencia; no esperar al ciclo mensual de parcheo.',
        'Aplicar la actualización del paquete afectado y reiniciar el servicio o el host según corresponda.',
        'Si no existe parche disponible, aplicar la mitigación del fabricante y compensar con reglas de detección específicas.',
        'Verificar con un nuevo escaneo que la vulnerabilidad desapareció.',
      ],
      responsable: RESP_SYS,
      esfuerzo: '1–2 días',
      plazoDias: 7,
      aceptacion: 'Cero vulnerabilidades KEV pendientes en el siguiente escaneo.',
      sprint: 's1',
    });
  }

  if (v && (v.resumen.critical > 0 || v.resumen.high > 0)) {
    const porHost = (v.porAgente ?? []).slice(0, 6);
    h.push({
      id: 'vul-criticas',
      dominio: 'vulnerabilidades',
      titulo: 'Volumen relevante de vulnerabilidades críticas y altas sin remediar',
      severidad: v.resumen.critical >= 20 ? 'alta' : 'media',
      confianza: 'alta',
      evidencia: `${fmt(v.resumen.critical)} críticas y ${fmt(v.resumen.high)} altas distribuidas en ${fmt(v.resumen.agentes)} host(s); ${fmt(v.resumen.cves)} CVE distintos.`,
      detalle: porHost.map((a) => `${a.agent} — ${fmt(a.total)} vulnerabilidades (${fmt(a.critical)} críticas, ${fmt(a.high)} altas)`),
      impacto: 'El volumen impide remediar todo a la vez; sin priorización por riesgo real (KEV + EPSS + exposición) el esfuerzo se dispersa en CVE que nunca se explotarán mientras quedan abiertos los que sí.',
      consulta: null,
      remediacion: [
        'Trabajar sobre la lista priorizada (KEV + EPSS + CVSS) del módulo de Vulnerabilidades, no sobre el listado completo.',
        'Definir un ciclo mensual de parcheo con ventana acordada y responsable por sistema.',
        'Empezar por los paquetes que concentran más CVE: una sola actualización suele cerrar decenas.',
        'Medir la reducción en cada informe para verificar que el ciclo funciona.',
      ],
      responsable: RESP_SYS,
      esfuerzo: '2 días/mes',
      plazoDias: 45,
      aceptacion: 'Reducción ≥ 50 % de críticas y altas en 45 días, con ciclo de parcheo documentado.',
      sprint: 's2',
    });
  }

  // ---------------- Configuración segura ----------------

  const sca = m.sca;
  if (sca && sca.resumen.scorePromedio > 0 && sca.resumen.scorePromedio < 80) {
    const peores = [...sca.agentes].sort((a, b) => a.score - b.score).slice(0, 5);
    h.push({
      id: 'har-sca',
      dominio: 'hardening',
      titulo: `Configuración segura en ${sca.resumen.scorePromedio} % del estándar CIS`,
      severidad: sca.resumen.scorePromedio < 55 ? 'alta' : 'media',
      confianza: 'alta',
      evidencia: `${fmt(sca.resumen.fail)} controles fallidos de ${fmt(sca.resumen.totalChecks)} evaluados en ${sca.resumen.agentesEvaluados} host(s).`,
      detalle: [
        ...peores.map((a) => `${a.agent} — ${a.score} % (${a.fail} fallidos de ${a.total}) — política ${a.policy}`),
        ...sca.topFallidos.slice(0, 5).map((c) => `Control fallido en ${c.count} host(s): ${c.title}`),
      ],
      impacto: 'El hardening determina hasta dónde llega un atacante después del acceso inicial. Un score bajo convierte un compromiso puntual en un compromiso del dominio.',
      consulta: null,
      remediacion: [
        'Priorizar los controles fallidos que se repiten en varios hosts: una sola corrección aplicada por configuración centralizada los cierra todos.',
        ...sca.topFallidos.slice(0, 3).map((c) => `«${c.title}»: ${(c.remediation || 'aplicar la remediación indicada por la política CIS').slice(0, 220)}`),
        'Aplicar los cambios primero en un host de prueba, validar que no rompe el servicio y luego desplegar.',
        'Reejecutar el escaneo SCA tras cada tanda para medir el avance.',
      ],
      responsable: RESP_SYS,
      esfuerzo: '3–5 días',
      plazoDias: 60,
      aceptacion: 'Score promedio ≥ 80 % y ningún host por debajo del 60 %.',
      sprint: 's2',
    });
  }

  // ---------------- Integridad de archivos ----------------

  const fimCriticos = m.fim.cambios.filter((c) => c.critico);
  if (fimCriticos.length > 0) {
    h.push({
      id: 'int-fim',
      dominio: 'integridad',
      titulo: `${fimCriticos.length} cambio(s) en archivos de configuración sensibles`,
      severidad: fimCriticos.some((c) => c.evento === 'deleted') ? 'alta' : 'media',
      confianza: 'media',
      evidencia: `De ${fmt(m.fim.total)} cambios registrados por el monitor de integridad (${m.fim.added} altas, ${m.fim.modified} modificaciones, ${m.fim.deleted} borrados), ${fimCriticos.length} afectan rutas críticas del sistema.`,
      detalle: fimCriticos.slice(0, 8).map((c) => `${c.agente} — ${c.evento} — ${c.ruta}${c.usuario ? ` (usuario ${c.usuario})` : ''} — nivel ${c.nivel}`),
      impacto: 'Los cambios en /etc/passwd, sudoers, claves SSH o binarios del sistema son el rastro habitual de una persistencia o una escalada de privilegios. También pueden ser mantenimiento legítimo: la diferencia solo se establece verificando.',
      consulta: dsl(IDX, [ventana(m), { exists: { field: 'syscheck.path' } }], {
        size: 100,
        _source: ['timestamp', 'agent.name', 'syscheck.path', 'syscheck.event', 'syscheck.uname_after', 'rule.level'],
        sort: [{ timestamp: 'desc' }],
      }),
      remediacion: [
        'Contrastar cada cambio con las ventanas de mantenimiento y los tickets de cambio aprobados.',
        'Para los no justificados: recuperar el diff (Wazuh conserva el contenido anterior en los archivos monitoreados con report_changes) y determinar qué se modificó.',
        'Verificar cuentas nuevas o con UID 0 si el cambio fue en /etc/passwd o /etc/shadow.',
        'Si no hay justificación, abrir caso y ejecutar recolección forense sobre el host (Velociraptor).',
      ],
      responsable: RESP_SOC,
      esfuerzo: '30 min por cambio',
      plazoDias: 3,
      aceptacion: 'Todos los cambios en rutas críticas justificados o escalados a caso.',
      sprint: 's1',
    });
  }

  // ---------------- Telemetría ----------------

  if (m.salud.agentesSinEventos.length > 0) {
    h.push({
      id: 'tel-mudos',
      dominio: 'telemetria',
      titulo: `${m.salud.agentesSinEventos.length} agente(s) activo(s) que no generaron un solo evento`,
      severidad: 'alta',
      confianza: 'alta',
      evidencia: `Los agentes figuran como conectados pero no aportaron ninguna alerta en la ventana analizada: ${m.salud.agentesSinEventos.join(', ')}.`,
      detalle: m.salud.agentesSinEventos.map((a) => `${a} — conectado, sin eventos en el periodo`),
      impacto: 'Un agente conectado que no reporta produce una falsa sensación de cobertura. Es peor que un agente caído, porque el caído sí se nota.',
      consulta: dsl(IDX, [ventana(m)], {
        size: 0,
        aggs: { agentes: { terms: { field: 'agent.name', size: 100 } } },
      }),
      remediacion: [
        'Verificar en el host el estado del servicio (`systemctl status wazuh-agent`) y la conectividad al manager (puerto 1514/TCP).',
        'Revisar `/var/ossec/logs/ossec.log` en el agente en busca de errores de envío o de cola llena.',
        'Comprobar que el agente tiene módulos de recolección habilitados en su `ossec.conf` (logcollector, syscheck, sca).',
        'Confirmar que el grupo asignado al agente incluye la configuración compartida esperada.',
      ],
      responsable: RESP_SYS,
      esfuerzo: '1 h por agente',
      plazoDias: 7,
      aceptacion: 'Todos los agentes activos generan eventos en el siguiente periodo.',
      sprint: 's1',
    });
  }

  if (m.salud.agentesDesconectados.length > 0) {
    h.push({
      id: 'tel-desconectados',
      dominio: 'telemetria',
      titulo: `${m.salud.agentesDesconectados.length} agente(s) desconectado(s)`,
      severidad: m.salud.agentesDesconectados.length > 2 ? 'alta' : 'media',
      confianza: 'alta',
      evidencia: `Cobertura efectiva de ${m.agentes.activos} de ${m.agentes.total} agentes registrados.`,
      detalle: m.salud.agentesDesconectados.slice(0, 10).map((a) => `${a.agente} — último contacto ${a.ultimoContacto || 'desconocido'}`),
      impacto: 'Sobre esos hosts no hay detección, ni inventario de vulnerabilidades, ni monitoreo de integridad. Son puntos ciegos completos.',
      consulta: null,
      remediacion: [
        'Determinar si el host sigue en operación o fue dado de baja sin retirar el agente del manager.',
        'Para los activos: reiniciar el servicio del agente y validar conectividad al manager.',
        'Para los dados de baja: eliminarlos del manager para que no distorsionen el indicador de cobertura.',
        'Configurar una alerta automática cuando un agente supere 24 h sin reportar.',
      ],
      responsable: RESP_SYS,
      esfuerzo: '2 h',
      plazoDias: 7,
      aceptacion: 'Cobertura ≥ 98 % sostenida y alerta de desconexión operativa.',
      sprint: 's1',
    });
  }

  if (m.salud.mayorHueco && m.salud.mayorHueco.horas >= (m.periodo.granularidad === 'hora' ? 3 : 24)) {
    h.push({
      id: 'tel-hueco',
      dominio: 'telemetria',
      titulo: 'Interrupción en la ingesta de eventos',
      severidad: 'alta',
      confianza: 'media',
      evidencia: `Se detectó un tramo de aproximadamente ${m.salud.mayorHueco.horas} h sin ningún evento, a partir de ${m.salud.mayorHueco.desde}. En total ${m.salud.bucketsVacios} de ${m.salud.bucketsTotales} tramos del periodo quedaron vacíos.`,
      detalle: [`Tramo más largo sin datos: ${m.salud.mayorHueco.horas} h desde ${m.salud.mayorHueco.desde}`],
      impacto: 'Durante una interrupción de ingesta no hay detección posible. Cualquier actividad ocurrida en esa ventana es irrecuperable salvo que los logs sigan en origen.',
      consulta: dsl(IDX, [ventana(m)], {
        size: 0,
        aggs: { t: { date_histogram: { field: 'timestamp', calendar_interval: '1h', min_doc_count: 0 } } },
      }),
      remediacion: [
        'Correlacionar el tramo vacío con reinicios del manager, del indexer o de la máquina virtual.',
        'Revisar `/var/ossec/logs/ossec.log` del manager y los logs del Indexer en esa franja.',
        'Verificar espacio en disco y estado de los índices (un índice en solo lectura por watermark detiene la ingesta).',
        'Configurar el monitor de salud del SIEM para alertar ante ausencia de eventos superior a 30 minutos.',
      ],
      responsable: RESP_SYS,
      esfuerzo: '3 h',
      plazoDias: 14,
      aceptacion: 'Sin tramos vacíos no justificados y alerta de ausencia de ingesta activa.',
      sprint: 's1',
    });
  }

  if (m.salud.versionesAgente.length > 2) {
    h.push({
      id: 'tel-versiones',
      dominio: 'telemetria',
      titulo: 'Parque de agentes con versiones heterogéneas',
      severidad: 'baja',
      confianza: 'alta',
      evidencia: `Conviven ${m.salud.versionesAgente.length} versiones distintas de agente en el parque.`,
      detalle: m.salud.versionesAgente.map((v2) => `${v2.version} — ${v2.agentes} agente(s)`),
      impacto: 'Las versiones antiguas carecen de módulos y correcciones recientes, lo que produce diferencias de cobertura difíciles de rastrear entre hosts.',
      consulta: null,
      remediacion: [
        'Definir la versión objetivo del parque (idealmente la del manager).',
        'Actualizar por lotes empezando por los hosts menos críticos.',
        'Validar tras cada lote que los agentes siguen reportando.',
      ],
      responsable: RESP_SYS,
      esfuerzo: '1 día',
      plazoDias: 90,
      aceptacion: 'Todo el parque en la versión objetivo, con una sola versión menor de diferencia como máximo.',
      sprint: 's3',
    });
  }

  // ---------------- Operación del SOC ----------------

  if (m.criticos > 0 && m.gestion.total === 0) {
    h.push({
      id: 'ope-sin-triage',
      dominio: 'operacion',
      titulo: 'Eventos críticos sin ningún caso abierto',
      severidad: 'alta',
      confianza: 'alta',
      evidencia: `Se registraron ${fmt(m.criticos)} eventos de nivel ≥ 12 y no se abrió ningún caso en el módulo de Incidentes durante el periodo.`,
      detalle: ['La detección funciona; el proceso de triage no está dejando rastro.'],
      impacto: 'Sin caso no hay responsable, ni tiempos medibles, ni evidencia de gestión ante una auditoría. El trabajo puede estar haciéndose, pero no es demostrable.',
      consulta: dsl(IDX, [ventana(m), { range: { 'rule.level': { gte: 12 } } }], {
        size: 50, sort: [{ timestamp: 'desc' }],
        _source: ['timestamp', 'agent.name', 'rule.id', 'rule.description', 'data.srcip'],
      }),
      remediacion: [
        'Definir la regla de escalamiento: todo evento de nivel ≥ 12 genera caso, aunque se cierre como falso positivo.',
        'Automatizar la creación del caso desde el Centro de Acción para no depender de la disciplina manual.',
        'Revisar retroactivamente los eventos críticos del periodo y documentar su desenlace.',
      ],
      responsable: RESP_SOC,
      esfuerzo: '4 h',
      plazoDias: 14,
      aceptacion: 'Todo evento crítico con caso asociado y desenlace documentado.',
      sprint: 's1',
    });
  }

  if (m.gestion.incumplidos.length > 0) {
    h.push({
      id: 'ope-sla',
      dominio: 'operacion',
      titulo: `${m.gestion.incumplidos.length} caso(s) atendido(s) fuera del tiempo comprometido`,
      severidad: m.gestion.incumplidos.length > 3 ? 'alta' : 'media',
      confianza: 'alta',
      evidencia: `Cumplimiento de tiempos de primera atención: ${m.gestion.cumplimientoSlaPct ?? 0} %.`,
      detalle: m.gestion.incumplidos.map((i) => `[${i.severidad}] ${i.titulo} — atendido a los ${i.minutos} min (objetivo ${i.objetivo} min)`),
      impacto: 'Cada minuto adicional amplía el alcance de un incidente. Los incumplimientos concentrados en una franja horaria suelen indicar un problema de cobertura del turno, no de capacidad.',
      consulta: null,
      remediacion: [
        'Analizar si los incumplimientos se concentran en una franja horaria o en un tipo de caso concreto.',
        'Ajustar el turno de guardia (módulo On-Call) para cubrir la franja descubierta.',
        'Activar el escalamiento automático cuando un caso se acerque al vencimiento del SLA.',
      ],
      responsable: RESP_SOC,
      esfuerzo: '4 h',
      plazoDias: 30,
      aceptacion: 'Cumplimiento de primera atención ≥ 90 % durante dos periodos consecutivos.',
      sprint: 's2',
    });
  }

  if (m.gestion.antiguos.length > 0) {
    h.push({
      id: 'ope-backlog',
      dominio: 'operacion',
      titulo: `${m.gestion.antiguos.length} caso(s) abierto(s) con más de una semana`,
      severidad: 'media',
      confianza: 'alta',
      evidencia: `El caso más antiguo lleva ${m.gestion.antiguos[0].dias} día(s) sin cerrar.`,
      detalle: m.gestion.antiguos.map((c) => `[${c.severidad}] ${c.titulo} — ${c.dias} días abierto`),
      impacto: 'Un caso abierto es un riesgo vigente y además distorsiona los indicadores de gestión, ocultando la carga real del equipo.',
      consulta: null,
      remediacion: [
        'Revisar cada caso: cerrar los ya resueltos de hecho y reasignar los bloqueados.',
        'Establecer una revisión semanal de vencimientos con el equipo.',
        'Documentar la causa del bloqueo cuando dependa de un tercero.',
      ],
      responsable: RESP_SOC,
      esfuerzo: '2 h/semana',
      plazoDias: 30,
      aceptacion: 'Ningún caso abierto con más de 15 días.',
      sprint: 'continuo',
    });
  }

  // ---------------- Picos de volumen ----------------

  if (m.picos.length > 0) {
    h.push({
      id: 'det-picos',
      dominio: 'deteccion',
      titulo: `${m.picos.length} pico(s) de volumen sin explicación documentada`,
      severidad: 'media',
      confianza: 'media',
      evidencia: `Se detectaron tramos con volumen superior al doble de la mediana del periodo. El mayor alcanzó ${fmt(m.picos[0].total)} eventos (${m.picos[0].vecesMedia}× la mediana).`,
      detalle: m.picos.map((p) => `${p.ts} — ${fmt(p.total)} eventos (${p.vecesMedia}× la mediana)`),
      impacto: 'Un pico puede ser un despliegue, un escaneo autorizado o el inicio de un ataque. Si no queda documentado, la siguiente vez tampoco se sabrá distinguir.',
      consulta: dsl(IDX, [ventana(m)], {
        size: 0,
        aggs: {
          t: {
            date_histogram: { field: 'timestamp', calendar_interval: '1h' },
            aggs: { reglas: { terms: { field: 'rule.id', size: 5 } } },
          },
        },
      }),
      remediacion: [
        'Para cada pico, identificar la regla y el agente que lo generaron con la consulta adjunta.',
        'Contrastar con ventanas de mantenimiento, despliegues y escaneos autorizados.',
        'Documentar la causa; si es recurrente y legítima, considerar una supresión acotada.',
      ],
      responsable: RESP_SOC,
      esfuerzo: '1 h por pico',
      plazoDias: 14,
      aceptacion: 'Todos los picos del periodo con causa identificada y registrada.',
      sprint: 's2',
    });
  }

  // ---------------- Inteligencia ----------------

  if (m.iocMatches.length === 0 && m.ipsExternas.length > 0) {
    h.push({
      id: 'int-feeds',
      dominio: 'inteligencia',
      titulo: 'Sin coincidencias de inteligencia pese a actividad externa relevante',
      severidad: 'baja',
      confianza: 'baja',
      evidencia: `Se observaron ${m.ipsExternas.length} direcciones públicas con actividad, pero ninguna coincidió con los indicadores cargados.`,
      detalle: ['Puede significar que las fuentes de inteligencia están desactualizadas o que su cobertura no aplica a esta superficie.'],
      impacto: 'Sin coincidencias no se sabe si la infraestructura está limpia o si la inteligencia no está mirando donde debe.',
      consulta: null,
      remediacion: [
        'Verificar en Threat Intel la fecha de última actualización de cada fuente.',
        'Añadir fuentes relevantes para el sector y la geografía de la organización.',
        'Cargar como IOC propios los indicadores extraídos de incidentes anteriores.',
      ],
      responsable: RESP_SOC,
      esfuerzo: '2 h',
      plazoDias: 30,
      aceptacion: 'Todas las fuentes actualizadas en las últimas 24 h.',
      sprint: 'continuo',
    });
  }

  return h.sort((a, b) => ORDEN_SEV[a.severidad] - ORDEN_SEV[b.severidad]);
}

// --------------------------------------------------------------------------
// Narrativa
// --------------------------------------------------------------------------

function resumenTecnico(m: TechMetrics, hs: HallazgoTecnico[]): string {
  const criticos = hs.filter((x) => x.severidad === 'critica');
  const altos = hs.filter((x) => x.severidad === 'alta');
  const partes: string[] = [];

  partes.push(
    `Durante ${m.periodo.label} la plataforma procesó **${fmt(m.total)}** eventos provenientes de ${m.agentes.activos} agente(s) activo(s), disparando **${fmt(m.reglasDistintas)}** reglas distintas. La distribución por severidad fue: ${fmt(m.criticos)} de nivel crítico (≥12), ${fmt(m.altos)} de nivel alto (8–11) y ${fmt(m.medios)} de nivel medio (5–7).`
  );

  if (m.variacion.total !== null || m.variacion.criticos !== null) {
    const t = m.variacion.total;
    const c = m.variacion.criticos;
    partes.push(
      `Respecto a la ventana equivalente anterior, el volumen total ${t === null ? 'no tiene base de comparación' : t === 0 ? 'se mantuvo igual' : t > 0 ? `creció un ${t} %` : `cayó un ${Math.abs(t)} %`} y los eventos críticos ${c === null ? 'no tienen base de comparación' : c === 0 ? 'se mantuvieron' : c > 0 ? `crecieron un ${c} %` : `cayeron un ${Math.abs(c)} %`}.`
    );
  }

  partes.push(
    `El análisis produjo **${hs.length} hallazgo(s)**: ${criticos.length} de severidad crítica, ${altos.length} alta y ${hs.length - criticos.length - altos.length} de severidad media o inferior. ${
      criticos.length > 0
        ? `Los críticos exigen acción en las próximas 24–72 horas: ${criticos.map((x) => x.titulo.toLowerCase()).join('; ')}.`
        : altos.length > 0
          ? `No hay hallazgos críticos; los de severidad alta deben cerrarse dentro del Sprint 1.`
          : 'No se identificaron hallazgos de severidad crítica ni alta en el periodo.'
    }`
  );

  if (m.salud.agentesSinEventos.length > 0 || m.salud.agentesDesconectados.length > 0) {
    partes.push(
      `**Advertencia sobre la cobertura de este informe:** ${m.salud.agentesDesconectados.length} agente(s) desconectado(s) y ${m.salud.agentesSinEventos.length} agente(s) activo(s) sin eventos. Las cifras anteriores describen únicamente la porción de la infraestructura que sí estuvo bajo observación.`
    );
  }

  return partes.join('\n\n');
}

function observaciones(m: TechMetrics, hs: HallazgoTecnico[]): string {
  const b: string[] = [];

  // Calidad de la señal
  const top5 = m.topReglas.slice(0, 5).reduce((s, r) => s + r.pctVolumen, 0);
  b.push(
    `**Calidad de la señal.** Las 5 reglas más frecuentes concentran el ${Math.round(top5)} % del volumen total. ${
      top5 >= 70
        ? 'Una concentración por encima del 70 % indica que el flujo está dominado por unos pocos patrones repetitivos: el resto de la telemetría queda enterrada bajo ellos y el coste de almacenamiento se dedica mayoritariamente a ruido.'
        : top5 >= 40
          ? 'Es una concentración esperable en infraestructuras pequeñas, pero conviene vigilar que no siga aumentando.'
          : 'La distribución es saludable: no hay una regla que monopolice el flujo.'
    }`
  );

  // Relación detección/gestión
  b.push(
    `**Del evento al caso.** Se generaron ${fmt(m.criticos + m.altos)} eventos de severidad alta o crítica y se abrieron ${fmt(m.gestion.total)} caso(s). ${
      m.gestion.total === 0
        ? 'La ausencia total de casos formales indica que el triage no está dejando rastro auditable, no necesariamente que no se haya trabajado.'
        : `La proporción resultante es de aproximadamente 1 caso por cada ${Math.max(1, Math.round((m.criticos + m.altos) / m.gestion.total))} eventos relevantes, lo que sugiere un filtrado ${(m.criticos + m.altos) / m.gestion.total > 500 ? 'muy agresivo: conviene verificar que no se esté descartando señal legítima' : 'razonable'}.`
    }`
  );

  // Superficie
  if (m.auth.fallos + m.auth.exitos > 0) {
    b.push(
      `**Autenticación.** ${fmt(m.auth.fallos)} fallos frente a ${fmt(m.auth.exitos)} éxitos (${m.auth.ratioFallo ?? 0} % de fallo). ${
        (m.auth.ratioFallo ?? 0) >= 40
          ? 'Un ratio así no se explica por error humano: corresponde a intentos automatizados.'
          : 'El ratio se mantiene dentro de lo que produce el error humano normal.'
      }${m.auth.usuariosAtacados.length ? ` La cuenta más solicitada fue «${m.auth.usuariosAtacados[0].usuario}» con ${fmt(m.auth.usuariosAtacados[0].fallos)} fallos.` : ''}`
    );
  }

  // MITRE
  if (m.mitre.total > 0) {
    b.push(
      `**Mapeo ATT&CK.** ${fmt(m.mitre.total)} eventos del periodo traen mapeo a ATT&CK, cubriendo ${m.mitre.tecnicas.length} técnica(s) sobre ${m.mitre.tacticas.length} táctica(s). ${
        m.mitre.tacticas.length > 0
          ? `La táctica dominante es ${m.mitre.tacticas[0].tactica} (${fmt(m.mitre.tacticas[0].conteo)} eventos).`
          : ''
      }${m.cobertura ? ` Frente al marco completo, ${m.cobertura.tacticsBlind} táctica(s) siguen sin ninguna detección.` : ''}`
    );
  } else {
    b.push('**Mapeo ATT&CK.** Ningún evento del periodo trae mapeo a técnicas de ATT&CK. Sin ese mapeo no es posible razonar sobre cobertura ni comunicar el riesgo en un lenguaje comparable con otras organizaciones.');
  }

  // Postura acumulada
  if (m.vuln || m.sca) {
    b.push(
      `**Deuda de seguridad acumulada.** ${m.vuln ? `${fmt(m.vuln.resumen.critical)} vulnerabilidades críticas y ${fmt(m.vuln.resumen.high)} altas${m.vuln.resumen.kev ? `, de las cuales ${fmt(m.vuln.resumen.kev)} con explotación activa confirmada` : ''}. ` : ''}${m.sca ? `Configuración segura en el ${m.sca.resumen.scorePromedio} % del estándar CIS. ` : ''}Ninguna de estas condiciones genera alertas por sí sola, pero son las que determinan el alcance real de un compromiso: no cambian el "si ocurre", cambian el "hasta dónde llega".`
    );
  }

  // Esfuerzo
  const s1 = hs.filter((x) => x.sprint === 's1').length;
  b.push(
    `**Carga de trabajo derivada.** El plan de acción contempla ${hs.length} acción(es), de las cuales ${s1} se concentran en el Sprint 1 (semanas 1–2). Si esa carga excede la capacidad del equipo, el criterio de corte debe ser la severidad, no el orden de aparición.`
  );

  return b.join('\n\n');
}

// --------------------------------------------------------------------------
// Plan, hoja de ruta e IOCs
// --------------------------------------------------------------------------

function fechaObjetivo(desdeIso: string, dias: number): string {
  return fechaLarga(new Date(new Date(desdeIso).getTime() + dias * 86_400_000).toISOString());
}

export function construirPlan(m: TechMetrics, hs: HallazgoTecnico[]): AccionTecnica[] {
  return hs.map((x, i) => ({
    n: i + 1,
    accion: x.remediacion[0] ?? x.titulo,
    dominio: x.dominio,
    severidad: x.severidad,
    responsable: x.responsable,
    esfuerzo: x.esfuerzo,
    plazo: fechaObjetivo(m.generadoEn, x.plazoDias),
    aceptacion: x.aceptacion,
    origen: x.titulo,
  }));
}

export function construirHojaRuta(hs: HallazgoTecnico[]): FaseTecnica[] {
  return SPRINTS.map((s) => {
    const items = hs.filter((x) => x.sprint === s.key);
    return {
      titulo: s.titulo,
      ventana: s.ventana,
      objetivo: s.objetivo,
      items: items.map((x) => ({ accion: x.aceptacion, dominio: DOMINIOS[x.dominio], severidad: x.severidad })),
      esfuerzoTotal: items.map((x) => x.esfuerzo).join(' + ') || '—',
    };
  }).filter((f) => f.items.length > 0);
}

/** Indicadores observados, listos para bloqueo o busqueda retrospectiva. */
export function construirIocs(m: TechMetrics): AnalisisTecnico['iocs'] {
  const out: AnalisisTecnico['iocs'] = [];
  for (const i of m.ipsExternas.slice(0, 10)) {
    out.push({
      tipo: 'IP',
      valor: i.ip,
      contexto: `${i.pais ?? 'origen desconocido'} · ${fmt(i.conteo)} eventos · nivel máx ${i.nivelMax} · ${i.reglasDistintas} reglas`,
    });
  }
  for (const i of m.iocMatches.slice(0, 10)) {
    out.push({ tipo: i.type.toUpperCase(), valor: i.value, contexto: `coincidencia con ${i.source} · ${fmt(i.alertCount)} alertas` });
  }
  for (const b of m.bloqueos.slice(0, 10)) {
    out.push({ tipo: 'IP bloqueada', valor: b.ip, contexto: `${b.pais ?? 'origen desconocido'} · ${b.motivo ?? 'sin motivo registrado'}` });
  }
  for (const u of m.auth.usuariosAtacados.slice(0, 5)) {
    out.push({ tipo: 'Cuenta', valor: u.usuario, contexto: `${fmt(u.fallos)} intentos fallidos de autenticación` });
  }
  return out;
}

// --------------------------------------------------------------------------

export function analizarTecnico(m: TechMetrics): AnalisisTecnico {
  const hallazgos = detectarHallazgos(m);
  return {
    hallazgos,
    resumen: resumenTecnico(m, hallazgos),
    observaciones: observaciones(m, hallazgos),
    plan: construirPlan(m, hallazgos),
    hojaRuta: construirHojaRuta(hallazgos),
    iocs: construirIocs(m),
  };
}
