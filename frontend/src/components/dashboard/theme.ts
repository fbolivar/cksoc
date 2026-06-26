/** Paleta y helpers compartidos por las graficas del dashboard. */

export const SEVERITY_COLORS = {
  baja: '#16a34a', // verde
  media: '#eab308', // amarillo
  alta: '#f97316', // naranja
  critica: '#ef4444', // rojo
} as const;

export const SEVERITY_LABELS = {
  baja: 'Baja',
  media: 'Media',
  alta: 'Alta',
  critica: 'Critica',
} as const;

// Paleta de graficas alineada a Parques Nacionales
export const CHART_GREEN = '#00a651'; // verde PNNC
export const CHART_BLUE = '#85B425'; // lima PNNC (nombre conservado por compatibilidad)
export const CHART_LIME = '#85B425';
export const CHART_TEAL = '#5fb0c9'; // verde-agua (categorias como MITRE)

/** Formatea numeros con separador de miles es-CO. */
export const fmt = (n: number) => n.toLocaleString('es-CO');

/** Estilo del tooltip de Recharts para el tema oscuro. */
export const tooltipStyle = {
  backgroundColor: 'rgba(13, 22, 19, 0.95)',
  border: '1px solid rgba(255,255,255,0.12)',
  borderRadius: 8,
  fontSize: 12,
  color: '#e6f2ec',
};
