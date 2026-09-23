/**
 * HexWatch -> SonicWall: bloqueo de IPs (adaptador de respuesta).
 * Expone las mismas funciones que fortigate.service (blockIP/unblockIP/listBlocked)
 * pero opera contra la API del SonicWall via el helper block_ip.py
 * (grupo de direcciones 'HexWatch-Blocked-IPs' + reglas DENY WAN->SOC/LAN).
 */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const run = promisify(execFile);
const HELPER = process.env.SONICWALL_HELPER || '/opt/hexwatch/sonicwall/block_ip.py';

export interface BannedEntry { ip: string; name: string; expiresAt: number | null; permanent: boolean }

export function isFortigateConfigured(): boolean { return true; }

export async function blockIP(ip: string, _expirySeconds?: number): Promise<void> {
  await run('python3', [HELPER, 'block', ip], { timeout: 30000 });
}

export async function unblockIP(ip: string): Promise<void> {
  await run('python3', [HELPER, 'unblock', ip], { timeout: 30000 });
}

export async function listBlocked(): Promise<BannedEntry[]> {
  const { stdout } = await run('python3', [HELPER, 'list'], { timeout: 30000 });
  const data = JSON.parse(stdout || '{"blocked":[]}');
  return ((data.blocked as string[]) || []).map((name) => {
    const ip = String(name).replace(/^HXW-Block-/, '');
    return { ip, name: ip, expiresAt: null, permanent: true };
  });
}
