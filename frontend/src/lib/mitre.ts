/** Tipos y API de MITRE ATT&CK. */
import { api } from './api';

export interface MitreTechnique {
  id: string;
  name: string;
  tactics: string[];
  count: number;
  maxLevel: number;
}

export interface MitreData {
  total: number;
  tecnicasDistintas: number;
  tactics: { tactic: string; count: number }[];
  techniques: MitreTechnique[];
}

export const mitreApi = {
  get: (hours: number) => api.get<MitreData>('/mitre', { params: { hours } }).then((r) => r.data),
};

/** Orden canonico de tacticas ATT&CK Enterprise (kill chain). */
export const TACTIC_ORDER = [
  'Reconnaissance',
  'Resource Development',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
];

/** Traduccion corta para subtitular cada tactica. */
export const TACTIC_ES: Record<string, string> = {
  Reconnaissance: 'Reconocimiento',
  'Resource Development': 'Desarrollo de recursos',
  'Initial Access': 'Acceso inicial',
  Execution: 'Ejecución',
  Persistence: 'Persistencia',
  'Privilege Escalation': 'Escalada de privilegios',
  'Defense Evasion': 'Evasión de defensas',
  'Credential Access': 'Acceso a credenciales',
  Discovery: 'Descubrimiento',
  'Lateral Movement': 'Movimiento lateral',
  Collection: 'Recolección',
  'Command and Control': 'Comando y control',
  Exfiltration: 'Exfiltración',
  Impact: 'Impacto',
};
