/** Paleta y helpers compartidos por las graficas del dashboard. */

export const SEVERITY_COLORS = {
  baja: '#03A64A', // verde corporativo PNNC
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

// Paleta de graficas alineada al Manual de Identidad Visual PNNC
export const CHART_GREEN = '#03A64A'; // verde corporativo PNNC
export const CHART_BLUE = '#049DD9'; // cian corporativo (nombre conservado por compatibilidad)
export const CHART_LIME = '#96BE54'; // verde institucional propio
export const CHART_TEAL = '#05C7F2'; // celeste corporativo (categorias como MITRE)

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
