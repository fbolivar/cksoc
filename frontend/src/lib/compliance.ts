/** Tipos, API y metadatos de Cumplimiento normativo. */
import { api } from './api';

export interface FrameworkResult {
  total: number;
  controlesCubiertos: number;
  controles: { id: string; count: number; level: number }[];
}
export interface ComplianceData {
  hours: number;
  frameworks: Record<string, FrameworkResult>;
}

export const complianceApi = {
  get: (hours: number) => api.get<ComplianceData>('/compliance', { params: { hours } }).then((r) => r.data),
};

export type Prioridad = 'Alta' | 'Media' | 'Baja' | 'Informativo';

export interface FrameworkMeta {
  key: string;
  label: string;
  prioridad: Prioridad;
  contexto: string;
  ref: (id: string) => string | null;
}

/** Marcos ordenados por prioridad segun el contexto de PNNC (entidad publica CO). */
export const FRAMEWORKS: FrameworkMeta[] = [
  {
    key: 'nist', label: 'NIST 800-53', prioridad: 'Alta',
    contexto: 'Base de los marcos de seguridad del Estado colombiano (MSPI/MinTIC) y alineado a ISO/IEC 27001.',
    ref: () => 'https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search',
  },
  {
    key: 'gdpr', label: 'GDPR', prioridad: 'Alta',
    contexto: 'Protección de datos personales; equivalente a la Ley 1581 (Habeas Data) de Colombia.',
    ref: () => 'https://gdpr-info.eu/',
  },
  {
    key: 'tsc', label: 'TSC (SOC 2)', prioridad: 'Media',
    contexto: 'Trust Services Criteria: seguridad, disponibilidad y confidencialidad del servicio.',
    ref: () => null,
  },
  {
    key: 'pci', label: 'PCI DSS', prioridad: 'Baja',
    contexto: 'Aplica solo si se procesan pagos con tarjeta (p. ej. tasas de ingreso); usualmente tercerizado.',
    ref: () => null,
  },
  {
    key: 'hipaa', label: 'HIPAA', prioridad: 'Informativo',
    contexto: 'Marco de salud de EE. UU.: no aplica a HexWatch. Se muestra de forma informativa.',
    ref: () => null,
  },
];

export const PRIORIDAD_COLOR: Record<Prioridad, string> = {
  Alta: '#22c55e',
  Media: '#eab308',
  Baja: '#94a3b8',
  Informativo: '#64748b',
};

/** Descripcion legible de los controles mas frecuentes (es-CO). */
export const CONTROL_DESC: Record<string, string> = {
  // NIST 800-53
  'AU.14': 'Auditoría de sesión', 'AC.7': 'Intentos de inicio de sesión fallidos',
  'AU.6': 'Revisión y análisis de registros de auditoría', 'AC.9': 'Notificación de inicio de sesión previo',
  'CM.1': 'Política de gestión de configuración', 'SI.7': 'Integridad de software y firmware',
  'AC.6': 'Privilegio mínimo', 'AU.5': 'Respuesta a fallos de auditoría',
  'SC.7': 'Protección de frontera (perímetro)', 'SI.4': 'Monitoreo del sistema de información',
  'SC.8': 'Confidencialidad en transmisión', 'AC.2': 'Gestión de cuentas', 'IA.4': 'Gestión de identificadores',
  'AU.4': 'Capacidad de almacenamiento de auditoría', 'AU.12': 'Generación de registros de auditoría',
  'AC.3': 'Control de acceso obligatorio', 'CM.3': 'Control de cambios de configuración',
  // GDPR
  'IV_32.2': 'Seguridad del tratamiento (Art. 32.2)', 'IV_35.7.d': 'Evaluación de impacto (Art. 35.7.d)',
  'II_5.1.f': 'Integridad y confidencialidad (Art. 5.1.f)',
  // TSC / SOC 2
  'CC7.2': 'Monitoreo de componentes del sistema', 'CC7.3': 'Evaluación de eventos de seguridad',
  'CC6.8': 'Prevención/detección de software no autorizado', 'CC7.1': 'Detección de cambios y vulnerabilidades',
  'CC6.1': 'Seguridad de acceso lógico', 'CC7.4': 'Respuesta a incidentes de seguridad',
  'CC8.1': 'Gestión de cambios', 'PI1.4': 'Integridad de procesamiento (salida)', 'PI1.5': 'Integridad de procesamiento (almacenamiento)',
  // PCI DSS
  '10.2.5': 'Registro del uso de autenticación', '10.6.1': 'Revisión diaria de registros',
  '2.2': 'Estándares de configuración de sistemas', '11.5': 'Detección de cambios (FIM)',
  '10.2.2': 'Registro de acciones de usuarios privilegiados', '11.2.1': 'Escaneo interno de vulnerabilidades',
  '11.2.3': 'Re-escaneo tras cambios significativos', '10.2.6': 'Registro de inicio/parada de auditoría',
  '1.4': 'Firewall en dispositivos', '11.4': 'IDS/IPS en el perímetro',
  // HIPAA
  '164.312.b': 'Controles de auditoría', '164.312.c.1': 'Integridad de la información',
  '164.312.c.2': 'Mecanismos de integridad', '164.312(a)(1)': 'Control de acceso',
  '164.312(a)(2)(iv)': 'Cifrado y descifrado', '164.312(e)(1)': 'Seguridad de transmisión',
  '164.312(e)(2)(i)': 'Controles de integridad en transmisión', '164.312(e)(2)(ii)': 'Cifrado en transmisión',
  '164.308(a)(3)(i)': 'Seguridad del personal', '164.308(a)(3)(ii)(A)': 'Autorización/supervisión',
};
