/**
 * Parser de la salida de los comandos apt (Linux) capturada por Velociraptor
 * (Linux.Sys.BashShell). El helper emite líneas marcadas:
 *   UPGRADABLE=<n>  SECURITY=<n>  REBOOT=yes|no
 *   ---LIST---  seguido de  pkg|version|sec(yes/no)
 *   RESULT=DONE            (scan)
 *   RESULT=EXITCODE=<n>    (apply / autoenable)
 */
import type { WingetPackage } from './winget.parse';

export interface AptScanResult {
  ok: boolean;
  upgradable: number;
  security: number;
  reboot: boolean;
  packages: WingetPackage[]; // reutiliza la forma; con flag `security`
  error?: string;
}

function num(s: string, key: string): number {
  const m = s.match(new RegExp(`${key}=(\\d+)`));
  return m ? Number(m[1]) : 0;
}

export function parseAptScan(stdout: string): AptScanResult {
  const s = stdout || '';
  if (!s.includes('RESULT=DONE') && !/UPGRADABLE=/.test(s)) {
    return { ok: false, upgradable: 0, security: 0, reboot: false, packages: [], error: 'No se pudo interpretar la salida de apt.' };
  }
  const reboot = /REBOOT=yes/.test(s);
  const lines = s.split(/\r?\n/);
  const start = lines.findIndex((l) => l.trim() === '---LIST---');
  const packages: WingetPackage[] = [];
  if (start >= 0) {
    for (let i = start + 1; i < lines.length; i++) {
      const line = lines[i];
      if (!line.trim() || line.includes('RESULT=')) break;
      const parts = line.split('|');
      if (parts.length < 2) continue;
      const [pkg, ver, sec] = parts;
      packages.push({
        name: pkg.trim(), id: pkg.trim(), current: '', available: (ver || '').trim(),
        source: 'apt', security: (sec || '').trim() === 'yes',
      });
    }
  }
  return { ok: true, upgradable: num(s, 'UPGRADABLE'), security: num(s, 'SECURITY'), reboot, packages };
}

export interface AptApplyResult {
  done: boolean;
  exitCode: number | null;
  reboot: boolean;
  clean: string;
  note?: string;
  error?: string;
}

export function parseAptApply(stdout: string): AptApplyResult {
  const s = stdout || '';
  const m = s.match(/RESULT=EXITCODE=(-?\d+)/);
  if (!m) return { done: false, exitCode: null, reboot: false, clean: '' };
  const exitCode = Number(m[1]);
  const reboot = /REBOOT=yes/.test(s);
  const note = s.includes('NO_SECURITY_UPDATES') ? 'no-security'
    : s.includes('AUTO=enabled') ? 'auto-enabled' : undefined;
  const clean = s.split(/\r?\n/).filter((l) => l.trim() && !l.includes('base64') && !l.includes('RESULT=')).join('\n').trim();
  return { done: true, exitCode, reboot, clean, note, error: exitCode === 0 ? undefined : `apt terminó con código ${exitCode}` };
}
