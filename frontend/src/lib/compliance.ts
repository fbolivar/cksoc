/** Tipos, API y metadatos de Cumplimiento normativo. */
import { api } from './api';

export interface Control { id: string; count: number; level: number; src?: string }
export interface FrameworkResult {
  total: number;
  controlesCubiertos: number;
  controles: Control[];
  derivado?: boolean;
}
export interface ComplianceData {
  hours: number;
  frameworks: Record<string, FrameworkResult>;
}

export const complianceApi = {
  get: (hours: number) => api.get<ComplianceData>('/compliance', { params: { hours } }).then((r) => r.data),
  downloadReport: async (hours: number) => {
    const res = await api.get('/compliance/report.pdf', { params: { hours }, responseType: 'blob', timeout: 90_000 });
    const url = URL.createObjectURL(res.data as Blob);
    const m = /filename="?([^"]+)"?/.exec((res.headers['content-disposition'] as string) ?? '');
    const a = document.createElement('a');
    a.href = url;
    a.download = m?.[1] ?? `Informe-Cumplimiento-${new Date().toISOString().slice(0, 10)}.pdf`;
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
  },
};

export type Prioridad = 'Alta' | 'Media' | 'Baja' | 'Informativo';
/** si = obligatorio/relevante para el cliente · opcional = a demanda · no = no aplica (referencia). */
export type Aplica = 'si' | 'opcional' | 'no';

export interface FrameworkMeta {
  key: string;
  label: string;
  prioridad: Prioridad;
  aplica: Aplica;
  catalogo: number;   // nº de controles técnicos monitoreables que contemplamos (denominador de la cobertura)
  contexto: string;
  nota?: string;      // aclaración de aplicabilidad / alcance
  derivado?: boolean; // construido por crosswalk (no lo etiqueta Wazuh)
  ref: (id: string) => string | null;
}

/**
 * Marcos ordenados por lo que le aplica al cliente (bufete de abogados colombiano
 * que trata datos personales): primero los obligatorios/relevantes, al final los que
 * NO aplican (se conservan como referencia, no se borran).
 */
export const FRAMEWORKS: FrameworkMeta[] = [
  {
    key: 'ley1581', label: 'Ley 1581 (Habeas Data)', prioridad: 'Alta', aplica: 'si', catalogo: 6,
    contexto: 'Ley 1581/2012 y Decreto 1074/2015: protección de datos personales en Colombia (vigilada por la SIC). Obligatoria para quien trata datos de terceros, como un bufete con datos de clientes.',
    nota: 'Capa TÉCNICA del principio de seguridad, medida por evidencia DIRECTA por tipo de evento: control de acceso, trazabilidad, detección de incidentes, integridad (FIM), vulnerabilidades y comunicaciones. La parte legal/organizacional —registro RNBD, autorizaciones, política de tratamiento, respuesta a titulares— se gestiona aparte y no se detecta por logs.',
    ref: () => 'https://www.sic.gov.co/tema/proteccion-de-datos-personales',
  },
  {
    key: 'iso27001', label: 'ISO/IEC 27001:2022', prioridad: 'Alta', aplica: 'si', catalogo: 15, derivado: true,
    contexto: 'Estándar internacional de gestión de seguridad de la información; el sello que piden los clientes corporativos. Cobertura del Anexo A (controles técnicos).',
    nota: 'Derivado por crosswalk desde los controles técnicos de NIST 800-53 que Wazuh etiqueta. Mide monitoreo de los controles del Anexo A, no la certificación (que requiere SGSI documentado + auditoría).',
    ref: () => 'https://www.iso.org/standard/27001',
  },
  {
    key: 'gdpr', label: 'GDPR', prioridad: 'Media', aplica: 'opcional', catalogo: 8,
    contexto: 'Reglamento europeo de protección de datos. Aplica si el bufete trata datos de titulares en la Unión Europea.',
    nota: 'Relevante solo si hay clientes o titulares de datos en la UE. Técnicamente converge con la Ley 1581.',
    ref: () => 'https://gdpr-info.eu/',
  },
  {
    key: 'nist', label: 'NIST 800-53', prioridad: 'Media', aplica: 'si', catalogo: 20,
    contexto: 'Catálogo técnico de controles; base sobre la que se derivan ISO 27001 y la capa técnica de la Ley 1581. Útil como detalle técnico de respaldo.',
    ref: () => 'https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search',
  },
  {
    key: 'tsc', label: 'TSC (SOC 2)', prioridad: 'Baja', aplica: 'opcional', catalogo: 12,
    contexto: 'Trust Services Criteria: seguridad, disponibilidad y confidencialidad del servicio.',
    nota: 'A demanda: solo si un cliente lo exige contractualmente.',
    ref: () => null,
  },
  {
    key: 'pci', label: 'PCI DSS', prioridad: 'Informativo', aplica: 'no', catalogo: 12,
    contexto: 'Estándar de la industria de tarjetas de pago.',
    nota: 'NO aplica a este cliente: no procesa pagos con tarjeta. Se muestra como referencia.',
    ref: () => null,
  },
  {
    key: 'hipaa', label: 'HIPAA', prioridad: 'Informativo', aplica: 'no', catalogo: 10,
    contexto: 'Ley de salud de Estados Unidos.',
    nota: 'NO aplica a este cliente: no es una entidad de salud de EE. UU. Se muestra como referencia.',
    ref: () => null,
  },
];

export const PRIORIDAD_COLOR: Record<Prioridad, string> = {
  Alta: '#22c55e',
  Media: '#eab308',
  Baja: '#94a3b8',
  Informativo: '#64748b',
};

export const APLICA_META: Record<Aplica, { label: string; color: string }> = {
  si: { label: 'Aplica', color: '#22c55e' },
  opcional: { label: 'Condicional', color: '#eab308' },
  no: { label: 'No aplica', color: '#64748b' },
};

/** Descripcion legible de los controles mas frecuentes (es-CO). */
export const CONTROL_DESC: Record<string, string> = {
  // Ley 1581 / Decreto 1074 (capa técnica)
  'L.SEG': 'Medidas de seguridad y control de acceso (Art. 4.g · Decreto 1074)',
  'L.CIFR': 'Confidencialidad y cifrado de datos personales',
  'L.TRAZ': 'Trazabilidad y registro de accesos a datos',
  'L.DET': 'Detección y reporte de incidentes a la SIC (Art. 17.n)',
  'L.INTEG': 'Integridad y calidad del dato (Art. 4.d)',
  'L.VULN': 'Gestión de vulnerabilidades técnicas',
  // ISO/IEC 27001:2022 Anexo A
  'A.5.15': 'Control de acceso', 'A.5.17': 'Información de autenticación',
  'A.8.2': 'Derechos de acceso privilegiado', 'A.8.5': 'Autenticación segura',
  'A.8.7': 'Protección contra malware', 'A.8.8': 'Gestión de vulnerabilidades técnicas',
  'A.8.9': 'Gestión de la configuración', 'A.8.15': 'Registro de eventos (logging)',
  'A.8.16': 'Actividades de monitoreo', 'A.8.20': 'Seguridad de las redes',
  'A.8.22': 'Segregación de redes', 'A.8.24': 'Uso de criptografía',
  'A.8.25': 'Ciclo de vida de desarrollo seguro', 'A.8.29': 'Pruebas de seguridad',
  'A.8.32': 'Gestión de cambios',
  // NIST 800-53
  'AU.14': 'Auditoría de sesión', 'AC.7': 'Intentos de inicio de sesión fallidos',
  'AU.6': 'Revisión y análisis de registros de auditoría', 'AC.9': 'Notificación de inicio de sesión previo',
  'CM.1': 'Política de gestión de configuración', 'SI.7': 'Integridad de software y firmware',
  'AC.6': 'Privilegio mínimo', 'AU.5': 'Respuesta a fallos de auditoría',
  'SC.7': 'Protección de frontera (perímetro)', 'SI.4': 'Monitoreo del sistema de información',
  'SC.8': 'Confidencialidad en transmisión', 'AC.2': 'Gestión de cuentas', 'IA.4': 'Gestión de identificadores',
  'AU.4': 'Capacidad de almacenamiento de auditoría', 'AU.12': 'Generación de registros de auditoría',
  'AC.3': 'Control de acceso obligatorio', 'CM.3': 'Control de cambios de configuración',
  'SA.11': 'Pruebas de seguridad del desarrollador', 'SI.2': 'Remediación de fallos', 'SI.3': 'Protección contra código malicioso',
  // GDPR
  'IV_32.2': 'Seguridad del tratamiento (Art. 32.2)', 'IV_35.7.d': 'Evaluación de impacto (Art. 35.7.d)',
  'II_5.1.f': 'Integridad y confidencialidad (Art. 5.1.f)',
  // TSC / SOC 2
  'CC7.2': 'Monitoreo de componentes del sistema', 'CC7.3': 'Evaluación de eventos de seguridad',
  'CC6.8': 'Prevención/detección de software no autorizado', 'CC7.1': 'Detección de cambios y vulnerabilidades',
  'CC6.1': 'Seguridad de acceso lógico', 'CC7.4': 'Respuesta a incidentes de seguridad',
  'CC8.1': 'Gestión de cambios', 'CC6.6': 'Perímetro lógico frente a amenazas externas', 'PI1.4': 'Integridad de procesamiento (salida)', 'PI1.5': 'Integridad de procesamiento (almacenamiento)',
  // PCI DSS
  '10.2.5': 'Registro del uso de autenticación', '10.6.1': 'Revisión diaria de registros',
  '2.2': 'Estándares de configuración de sistemas', '11.5': 'Detección de cambios (FIM)',
  '10.2.2': 'Registro de acciones de usuarios privilegiados', '11.2.1': 'Escaneo interno de vulnerabilidades',
  '11.2.3': 'Re-escaneo tras cambios significativos', '10.2.6': 'Registro de inicio/parada de auditoría',
  '1.4': 'Firewall en dispositivos', '11.4': 'IDS/IPS en el perímetro', '1.3.4': 'Restricción de tráfico saliente', '8.1.6': 'Bloqueo tras intentos fallidos', '6.5': 'Vulnerabilidades comunes de código',
  // HIPAA
  '164.312.b': 'Controles de auditoría', '164.312.c.1': 'Integridad de la información',
  '164.312.c.2': 'Mecanismos de integridad', '164.312.a.1': 'Control de acceso',
  '164.312.a.2.I': 'Identificación única de usuario', '164.312.a.2.II': 'Acceso de emergencia',
  '164.312.e.1': 'Seguridad de transmisión',
};
