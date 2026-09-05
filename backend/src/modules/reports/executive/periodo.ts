/**
 * Resolucion de PERIODOS para el informe gerencial.
 *
 * El informe ya no esta atado a un mes: acepta presets (mes actual, mes
 * anterior, trimestre, semestre, año, ultimos N dias) o un rango de fechas
 * arbitrario (desde / hasta).
 *
 * Todas las fechas de entrada/salida visibles son fechas LOCALES de Colombia
 * (America/Bogota, UTC-5 sin horario de verano). Internamente se convierten a
 * instantes UTC para consultar el Indexer y PostgreSQL.
 */

/** Colombia no aplica horario de verano: offset fijo. */
const TZ_OFFSET_HOURS = -5;

const MESES = [
  'enero', 'febrero', 'marzo', 'abril', 'mayo', 'junio',
  'julio', 'agosto', 'septiembre', 'octubre', 'noviembre', 'diciembre',
];

export type PresetPeriodo =
  | 'ultimas-24h'
  | 'ultimas-72h'
  | 'hoy'
  | 'ultimos-7d'
  | 'ultimos-30d'
  | 'ultimos-90d'
  | 'mes-actual'
  | 'mes-anterior'
  | 'trimestre-actual'
  | 'trimestre-anterior'
  | 'semestre-actual'
  | 'anio-actual'
  | 'anio-anterior'
  | 'personalizado';

export const PRESETS: { value: PresetPeriodo; label: string }[] = [
  { value: 'mes-anterior', label: 'Mes anterior' },
  { value: 'mes-actual', label: 'Mes actual (a la fecha)' },
  { value: 'trimestre-anterior', label: 'Trimestre anterior' },
  { value: 'trimestre-actual', label: 'Trimestre actual (a la fecha)' },
  { value: 'semestre-actual', label: 'Semestre actual (a la fecha)' },
  { value: 'anio-actual', label: 'Año actual (a la fecha)' },
  { value: 'anio-anterior', label: 'Año anterior' },
  { value: 'ultimos-7d', label: 'Últimos 7 días' },
  { value: 'ultimos-30d', label: 'Últimos 30 días' },
  { value: 'ultimos-90d', label: 'Últimos 90 días' },
  { value: 'personalizado', label: 'Rango personalizado' },
];

/**
 * Presets del informe TECNICO: incluye ventanas por horas (turno / guardia),
 * que no tienen sentido en un informe de gerencia.
 */
export const PRESETS_TECNICO: { value: PresetPeriodo; label: string }[] = [
  { value: 'ultimas-24h', label: 'Últimas 24 horas' },
  { value: 'ultimas-72h', label: 'Últimas 72 horas' },
  { value: 'ultimos-7d', label: 'Últimos 7 días' },
  { value: 'ultimos-30d', label: 'Últimos 30 días' },
  { value: 'mes-anterior', label: 'Mes anterior' },
  { value: 'mes-actual', label: 'Mes actual (a la fecha)' },
  { value: 'ultimos-90d', label: 'Últimos 90 días' },
  { value: 'personalizado', label: 'Rango personalizado' },
];

export interface Periodo {
  /** Preset con el que se construyo (informativo). */
  preset: PresetPeriodo;
  /** Fecha local inicial inclusive, YYYY-MM-DD. */
  desde: string;
  /** Fecha local final INCLUSIVE, YYYY-MM-DD. */
  hasta: string;
  /** Instante UTC inicial inclusive (ISO) para consultas. */
  gte: string;
  /** Instante UTC final exclusivo (ISO) para consultas. */
  lt: string;
  /** Numero de dias calendario cubiertos. */
  dias: number;
  /** Etiqueta corta: "junio de 2026", "segundo trimestre de 2026", "1 al 15 de julio de 2026". */
  label: string;
  /** Texto largo del rango: "del 1 al 30 de junio de 2026". */
  rangoTexto: string;
  /** Mes de referencia YYYY-MM (mes en el que inicia el periodo). Compatibilidad. */
  mes: string;
  /** Granularidad sugerida para la serie temporal. */
  granularidad: 'hora' | 'dia' | 'semana' | 'mes';
  /** true si es una ventana rodante por horas (no un rango de dias completos). */
  porHoras?: boolean;
}

// --------------------------------------------------------------------------
// Utilidades de fecha local (Bogota)
// --------------------------------------------------------------------------

/** Instante UTC correspondiente a las 00:00 hora local de una fecha local. */
function localMidnightUtc(y: number, mIdx: number, d: number): Date {
  return new Date(Date.UTC(y, mIdx, d, -TZ_OFFSET_HOURS, 0, 0, 0));
}

/** Fecha local (Y, M, D) de "ahora". */
function hoyLocal(): { y: number; m: number; d: number } {
  const n = new Date(Date.now() + TZ_OFFSET_HOURS * 3600_000);
  return { y: n.getUTCFullYear(), m: n.getUTCMonth(), d: n.getUTCDate() };
}

function ymd(y: number, mIdx: number, d: number): string {
  return `${y}-${String(mIdx + 1).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
}

function parseYmd(s: string): { y: number; m: number; d: number } | null {
  const mt = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s.trim());
  if (!mt) return null;
  const y = Number(mt[1]);
  const m = Number(mt[2]) - 1;
  const d = Number(mt[3]);
  if (m < 0 || m > 11 || d < 1 || d > 31) return null;
  // Valida que la fecha exista realmente (p.ej. 31 de febrero)
  const probe = new Date(Date.UTC(y, m, d));
  if (probe.getUTCMonth() !== m || probe.getUTCDate() !== d) return null;
  return { y, m, d };
}

/** Suma dias a una fecha local. */
function addDays(f: { y: number; m: number; d: number }, n: number): { y: number; m: number; d: number } {
  const t = new Date(Date.UTC(f.y, f.m, f.d + n));
  return { y: t.getUTCFullYear(), m: t.getUTCMonth(), d: t.getUTCDate() };
}

function ultimoDiaDelMes(y: number, mIdx: number): number {
  return new Date(Date.UTC(y, mIdx + 1, 0)).getUTCDate();
}

// --------------------------------------------------------------------------
// Etiquetas en lenguaje natural
// --------------------------------------------------------------------------

const ORDINAL_TRIM = ['primer', 'segundo', 'tercer', 'cuarto'];

function etiquetar(
  a: { y: number; m: number; d: number },
  b: { y: number; m: number; d: number }
): { label: string; rangoTexto: string } {
  const rangoTexto =
    a.y === b.y && a.m === b.m
      ? `del ${a.d} al ${b.d} de ${MESES[a.m]} de ${a.y}`
      : a.y === b.y
        ? `del ${a.d} de ${MESES[a.m]} al ${b.d} de ${MESES[b.m]} de ${a.y}`
        : `del ${a.d} de ${MESES[a.m]} de ${a.y} al ${b.d} de ${MESES[b.m]} de ${b.y}`;

  // Mes calendario completo
  if (a.y === b.y && a.m === b.m && a.d === 1 && b.d === ultimoDiaDelMes(a.y, a.m)) {
    return { label: `${MESES[a.m]} de ${a.y}`, rangoTexto };
  }
  // Año calendario completo
  if (a.y === b.y && a.m === 0 && a.d === 1 && b.m === 11 && b.d === 31) {
    return { label: `año ${a.y}`, rangoTexto };
  }
  // Trimestre calendario completo
  if (a.y === b.y && a.d === 1 && a.m % 3 === 0 && b.m === a.m + 2 && b.d === ultimoDiaDelMes(b.y, b.m)) {
    return { label: `${ORDINAL_TRIM[a.m / 3]} trimestre de ${a.y}`, rangoTexto };
  }
  // Semestre calendario completo
  if (a.y === b.y && a.d === 1 && (a.m === 0 || a.m === 6) && b.m === a.m + 5 && b.d === ultimoDiaDelMes(b.y, b.m)) {
    return { label: `${a.m === 0 ? 'primer' : 'segundo'} semestre de ${a.y}`, rangoTexto };
  }
  // Rango libre
  return { label: rangoTexto.replace(/^del /, '').replace(/^/, '').trim(), rangoTexto };
}

// --------------------------------------------------------------------------
// Construccion
// --------------------------------------------------------------------------

function construir(
  preset: PresetPeriodo,
  a: { y: number; m: number; d: number },
  b: { y: number; m: number; d: number }
): Periodo {
  const gteDate = localMidnightUtc(a.y, a.m, a.d);
  // `hasta` es inclusivo => el limite superior exclusivo es el dia siguiente 00:00 local
  const nextB = addDays(b, 1);
  const ltDate = localMidnightUtc(nextB.y, nextB.m, nextB.d);
  const dias = Math.max(1, Math.round((ltDate.getTime() - gteDate.getTime()) / 86_400_000));
  const { label, rangoTexto } = etiquetar(a, b);
  return {
    preset,
    desde: ymd(a.y, a.m, a.d),
    hasta: ymd(b.y, b.m, b.d),
    gte: gteDate.toISOString(),
    lt: ltDate.toISOString(),
    dias,
    label,
    rangoTexto,
    mes: `${a.y}-${String(a.m + 1).padStart(2, '0')}`,
    granularidad: dias <= 45 ? 'dia' : dias <= 200 ? 'semana' : 'mes',
  };
}

/** Ventana rodante de las ultimas N horas (informe tecnico / turno). */
function construirHoras(preset: PresetPeriodo, horas: number): Periodo {
  const ahora = new Date();
  // Se redondea a la hora en curso para que los cortes sean reproducibles.
  const lt = new Date(Math.ceil(ahora.getTime() / 3600_000) * 3600_000);
  const gte = new Date(lt.getTime() - horas * 3600_000);
  const local = (d: Date) => new Date(d.getTime() + TZ_OFFSET_HOURS * 3600_000);
  const a = local(gte);
  const b = local(new Date(lt.getTime() - 1));
  const hh = (d: Date) => `${String(d.getUTCHours()).padStart(2, '0')}:00`;
  const rangoTexto =
    `desde el ${a.getUTCDate()} de ${MESES[a.getUTCMonth()]} a las ${hh(a)} ` +
    `hasta el ${b.getUTCDate()} de ${MESES[b.getUTCMonth()]} a las ${hh(local(lt))} (hora de Colombia)`;
  return {
    preset,
    desde: ymd(a.getUTCFullYear(), a.getUTCMonth(), a.getUTCDate()),
    hasta: ymd(b.getUTCFullYear(), b.getUTCMonth(), b.getUTCDate()),
    gte: gte.toISOString(),
    lt: lt.toISOString(),
    dias: Math.max(1, Math.round(horas / 24)),
    label: `últimas ${horas} horas`,
    rangoTexto,
    mes: `${a.getUTCFullYear()}-${String(a.getUTCMonth() + 1).padStart(2, '0')}`,
    granularidad: 'hora',
    porHoras: true,
  };
}

export class PeriodoInvalido extends Error {}

/** Limite de tamaño para evitar consultas desmedidas al Indexer. */
const MAX_DIAS = 400;

/**
 * Resuelve un periodo a partir de un preset o de un rango explicito.
 * Si se envian `desde`/`hasta` validos, mandan sobre el preset.
 */
export function resolvePeriodo(input: {
  preset?: string;
  desde?: string;
  hasta?: string;
}): Periodo {
  const hoy = hoyLocal();

  // 1) Rango explicito
  if (input.desde && input.hasta) {
    const a = parseYmd(input.desde);
    const b = parseYmd(input.hasta);
    if (!a || !b) throw new PeriodoInvalido('Fechas inválidas (formato esperado AAAA-MM-DD)');
    const p = construir((input.preset as PresetPeriodo) || 'personalizado', a, b);
    if (new Date(p.gte) >= new Date(p.lt)) {
      throw new PeriodoInvalido('La fecha inicial debe ser anterior o igual a la fecha final');
    }
    if (p.dias > MAX_DIAS) {
      throw new PeriodoInvalido(`El periodo no puede superar ${MAX_DIAS} días`);
    }
    return p;
  }

  // 2) Presets
  const preset = (input.preset || 'mes-anterior') as PresetPeriodo;
  const ayer = addDays(hoy, -1);

  switch (preset) {
    case 'ultimas-24h':
      return construirHoras(preset, 24);
    case 'ultimas-72h':
      return construirHoras(preset, 72);
    case 'hoy':
      return construir(preset, hoy, hoy);
    case 'ultimos-7d':
      return construir(preset, addDays(ayer, -6), ayer);
    case 'ultimos-30d':
      return construir(preset, addDays(ayer, -29), ayer);
    case 'ultimos-90d':
      return construir(preset, addDays(ayer, -89), ayer);
    case 'mes-actual':
      return construir(preset, { y: hoy.y, m: hoy.m, d: 1 }, hoy);
    case 'mes-anterior': {
      const pm = new Date(Date.UTC(hoy.y, hoy.m - 1, 1));
      const y = pm.getUTCFullYear();
      const m = pm.getUTCMonth();
      return construir(preset, { y, m, d: 1 }, { y, m, d: ultimoDiaDelMes(y, m) });
    }
    case 'trimestre-actual': {
      const qm = Math.floor(hoy.m / 3) * 3;
      return construir(preset, { y: hoy.y, m: qm, d: 1 }, hoy);
    }
    case 'trimestre-anterior': {
      const qStart = new Date(Date.UTC(hoy.y, Math.floor(hoy.m / 3) * 3 - 3, 1));
      const y = qStart.getUTCFullYear();
      const m = qStart.getUTCMonth();
      const fin = new Date(Date.UTC(y, m + 3, 0));
      return construir(preset, { y, m, d: 1 }, { y: fin.getUTCFullYear(), m: fin.getUTCMonth(), d: fin.getUTCDate() });
    }
    case 'semestre-actual': {
      const sm = hoy.m < 6 ? 0 : 6;
      return construir(preset, { y: hoy.y, m: sm, d: 1 }, hoy);
    }
    case 'anio-actual':
      return construir(preset, { y: hoy.y, m: 0, d: 1 }, hoy);
    case 'anio-anterior':
      return construir(preset, { y: hoy.y - 1, m: 0, d: 1 }, { y: hoy.y - 1, m: 11, d: 31 });
    default:
      throw new PeriodoInvalido('Periodo no reconocido. Indique un preset válido o un rango de fechas.');
  }
}

/**
 * Periodo inmediatamente anterior, de la MISMA duracion, para comparar.
 * Ej: junio (30 d) -> los 30 dias previos al 1 de junio.
 */
export function periodoAnterior(p: Periodo): Periodo {
  if (p.porHoras) {
    // Ventana rodante: se desplaza el mismo numero de milisegundos hacia atras.
    const dur = new Date(p.lt).getTime() - new Date(p.gte).getTime();
    const lt = new Date(p.gte);
    const gte = new Date(lt.getTime() - dur);
    const horas = Math.round(dur / 3600_000);
    return {
      ...p,
      preset: 'personalizado',
      gte: gte.toISOString(),
      lt: lt.toISOString(),
      label: `${horas} horas previas`,
      rangoTexto: `las ${horas} horas inmediatamente anteriores`,
    };
  }
  const a = parseYmd(p.desde)!;
  const finPrev = addDays(a, -1);
  const iniPrev = addDays(finPrev, -(p.dias - 1));
  return construir('personalizado', iniPrev, finPrev);
}

/** Formatea una fecha ISO como "15 de junio de 2026" (hora local Colombia). */
export function fechaLarga(iso: string): string {
  const t = new Date(new Date(iso).getTime() + TZ_OFFSET_HOURS * 3600_000);
  return `${t.getUTCDate()} de ${MESES[t.getUTCMonth()]} de ${t.getUTCFullYear()}`;
}

/** Etiqueta corta de un bucket de la serie temporal. */
export function etiquetaBucket(iso: string, g: Periodo['granularidad']): string {
  const t = new Date(new Date(iso).getTime() + TZ_OFFSET_HOURS * 3600_000);
  if (g === 'hora') return `${String(t.getUTCHours()).padStart(2, '0')}:00`;
  if (g === 'mes') return `${MESES[t.getUTCMonth()].slice(0, 3)} ${String(t.getUTCFullYear()).slice(2)}`;
  return `${t.getUTCDate()}/${t.getUTCMonth() + 1}`;
}
