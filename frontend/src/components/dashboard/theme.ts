/** Paleta y helpers compartidos por las graficas del dashboard (tema claro HexWatch). */

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

// Paleta de graficas HexWatch (coral primario + apoyos legibles en claro)
export const CHART_GREEN = '#16a34a';
export const CHART_BLUE = '#2563eb';
export const CHART_LIME = '#65a30d';
export const CHART_TEAL = '#0891b2';
export const CHART_CORAL = '#f0512e';

// Colores de ejes/rejilla legibles tanto en claro como en oscuro.
export const CHART_AXIS = '#71717a'; // gris medio (zinc-500)
export const CHART_GRID = 'rgba(113,113,122,0.18)';

/** Formatea numeros con separador de miles es-CO. */
export const fmt = (n: number) => n.toLocaleString('es-CO');

/** Estilo del tooltip de Recharts para el tema claro. */
export const tooltipStyle = {
  backgroundColor: '#ffffff',
  border: '1px solid rgba(17,17,17,0.08)',
  borderRadius: 12,
  fontSize: 12,
  color: '#171717',
  boxShadow: '0 10px 30px -12px rgba(17,17,17,0.25)',
};
