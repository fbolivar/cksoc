/**
 * Parser de la salida de `winget upgrade` capturada por Velociraptor.
 * La salida trae ruido (banner de PowerShell, el blob -EncodedCommand y el prompt);
 * anclamos en la línea de guiones para localizar la tabla y parseamos por OFFSETS
 * de columna (posicional, robusto ante idioma del SO: Name/Id/Version/Available/Source
 * o Nombre/Id/Versión/Disponible/Origen). El backend nunca confía en el nombre de la
 * columna, sólo en su posición.
 */
export interface WingetPackage {
  name: string;
  id: string;
  current: string;   // versión instalada ("Unknown" si winget no la conoce)
  available: string; // versión disponible
  source: string;
  security?: boolean; // Linux/apt: si el paquete viene del repo de seguridad
}

export interface WingetListResult {
  ok: boolean;
  packages: WingetPackage[];
  clean: string;          // texto legible de la tabla winget (sin banner/blob)
  note?: string;          // 'up-to-date', 'no-appinstaller', 'no-winget', 'error'
  error?: string;
}

const DASHES = /^[\s-]*-{8,}[\s-]*$/;

// Paquetes de framework/runtime UWP: winget los LISTA como actualizables pero no los
// puede actualizar en modo silencioso (fallan con 0x80070057 E_INVALIDARG). Los mantiene
// la Microsoft Store o se actualizan como dependencia de otras apps UWP; no son parches
// accionables. Se ocultan de la lista para no meter ruido ni errores confusos.
// NOTA: NO incluye Microsoft.VCRedist.* (los redistribuibles Win32 SÍ se parchean por winget).
const FRAMEWORK_ID_RE = /^(Microsoft\.VCLibs\.|Microsoft\.UI\.Xaml\.|Microsoft\.NET\.Native\.|Microsoft\.WindowsAppRuntime\.|Microsoft\.WinAppRuntime|Microsoft\.Services\.Store\.Engagement|Microsoft\.Advertising\.Xaml)/i;

export function isFrameworkPackage(id: string): boolean {
  return FRAMEWORK_ID_RE.test(id || '');
}

/** Índices de inicio de cada columna a partir de la fila de cabecera. */
function columnStarts(header: string): number[] {
  const starts: number[] = [];
  const re = /(\S+)/g;   // primer carácter de cada "palabra" de cabecera
  let m: RegExpExecArray | null;
  let prevEnd = -1;
  while ((m = re.exec(header))) {
    // Palabras separadas por 2+ espacios inician una columna nueva.
    if (m.index - prevEnd >= 2 || starts.length === 0) starts.push(m.index);
    prevEnd = m.index + m[0].length;
  }
  return starts;
}

function slice(line: string, starts: number[], i: number): string {
  const from = starts[i];
  const to = i + 1 < starts.length ? starts[i + 1] : line.length;
  return (line.slice(from, to) || '').trim();
}

export function parseWingetList(stdout: string): WingetListResult {
  const s = stdout || '';
  if (s.includes('RESULT=NO_APPINSTALLER'))
    return { ok: false, packages: [], clean: '', note: 'no-appinstaller', error: 'winget (App Installer) no está instalado en el equipo.' };
  if (s.includes('RESULT=NO_WINGET_EXE'))
    return { ok: false, packages: [], clean: '', note: 'no-winget', error: 'No se encontró winget.exe en el equipo.' };

  const lines = s.split(/\r?\n/);
  const dashIdx = lines.findIndex((l) => DASHES.test(l) && (l.match(/-/g) || []).length >= 8);
  if (dashIdx <= 0) {
    // Sin tabla: puede que esté todo al día.
    if (/No (installed )?(applicable )?(package|upgrade)/i.test(s) || /\b0 upgrades? available/i.test(s))
      return { ok: true, packages: [], clean: '', note: 'up-to-date' };
    return { ok: false, packages: [], clean: '', note: 'error', error: 'No se pudo interpretar la salida de winget.' };
  }
  const starts = columnStarts(lines[dashIdx - 1]);
  const pkgs: WingetPackage[] = [];
  const clean: string[] = [lines[dashIdx - 1], lines[dashIdx]];
  for (let i = dashIdx + 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) break;
    if (/upgrades? available/i.test(line) || line.includes('RESULT=') || line.trim().startsWith('PS ')) break;
    clean.push(line);
    const id = slice(line, starts, 1);
    if (!id) continue;
    if (isFrameworkPackage(id)) continue; // frameworks UWP: no accionables por winget
    pkgs.push({
      name: slice(line, starts, 0),
      id,
      current: slice(line, starts, 2),
      available: slice(line, starts, 3),
      source: starts.length > 4 ? slice(line, starts, 4) : '',
    });
  }
  return { ok: true, packages: pkgs, clean: clean.join('\n') };
}

export interface WingetApplyResult {
  done: boolean;
  exitCode: number | null;
  clean: string;
  error?: string;
}

/** Interpreta la salida de un `winget upgrade --id ...` (aplicación). */
export function parseWingetApply(stdout: string): WingetApplyResult {
  const s = stdout || '';
  if (s.includes('RESULT=NO_APPINSTALLER')) return { done: true, exitCode: 10, clean: '', error: 'winget no está instalado.' };
  if (s.includes('RESULT=NO_WINGET_EXE')) return { done: true, exitCode: 11, clean: '', error: 'No se encontró winget.exe.' };
  const m = s.match(/RESULT=EXITCODE=(-?\d+)/);
  if (!m) return { done: false, exitCode: null, clean: '' };
  const exitCode = Number(m[1]);
  // Texto útil: entre el prompt/blob y el marcador RESULT.
  const lines = s.split(/\r?\n/);
  const start = lines.findIndex((l) => !l.includes('EncodedCommand') && !/^PS /.test(l) && !/Windows PowerShell|Copyright/.test(l) && l.trim());
  const end = lines.findIndex((l) => l.includes('RESULT=EXITCODE='));
  const clean = lines.slice(start >= 0 ? start : 0, end >= 0 ? end : undefined).filter((l) => !l.includes('EncodedCommand')).join('\n').trim();
  return { done: true, exitCode, clean };
}

/** ¿La salida indica que el comando ya terminó (para dejar de sondear)? */
export function isComplete(stdout: string): boolean {
  const s = stdout || '';
  return s.includes('RESULT=DONE') || s.includes('RESULT=EXITCODE=') || s.includes('RESULT=NO_');
}
