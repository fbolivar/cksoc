/**
 * Remediación (MVP): actualizar Windows/apps con winget en endpoints, vía Velociraptor.
 *
 * Guardrails (viven aquí, en la app; Velociraptor sólo ejecuta):
 *  - Sólo Windows y sólo agentes en línea.
 *  - `scan` es de SÓLO LECTURA (winget upgrade = lista, no instala).
 *  - `apply` (instalar/actualizar) está restringido a los HOSTS PILOTO
 *    (REMEDIATION_PILOT_HOSTS) hasta que se habilite explícitamente para el resto.
 *  - Cada acción se persiste como job auditable y la sesión PowerShell se CANCELA
 *    al capturar el resultado (no se dejan sesiones vivas en el endpoint).
 *
 * La finalización se detecta por el marcador RESULT=... en stdout (el flow del
 * artefacto es stateful y no pasa a FINISHED por sí solo).
 */
import { randomUUID } from 'node:crypto';
import { runHelper } from '../velociraptor/velociraptor.helper';
import { query } from '../../config/db';
import { logger } from '../../config/logger';
import { parseWingetList, parseWingetApply, isComplete } from './winget.parse';
import { parseAptScan, parseAptApply } from './apt.parse';

type Platform = 'windows' | 'linux';

const PILOT_HOSTS = (process.env.REMEDIATION_PILOT_HOSTS || '')
  .split(',').map((h) => h.trim().toUpperCase()).filter(Boolean);
// Sin lista de piloto (o con '*') = aplicación habilitada en CUALQUIER equipo.
// Para volver a restringir, poner REMEDIATION_PILOT_HOSTS=host1,host2 en el .env.
const ALLOW_ALL = PILOT_HOSTS.length === 0 || PILOT_HOSTS.includes('*');
const JOB_MAX_MIN = Number(process.env.REMEDIATION_JOB_MAX_MIN || 25); // corte de seguridad
const HOST_RE = /^[A-Za-z0-9._-]{1,120}$/;
const PKG_RE = /^[A-Za-z0-9._+-]{1,160}$/;

export function isPilotHost(host: string): boolean {
  return ALLOW_ALL || PILOT_HOSTS.includes(String(host || '').toUpperCase());
}
export function allowAllHosts(): boolean { return ALLOW_ALL; }
export function pilotHosts(): string[] { return [...PILOT_HOSTS]; }

export interface RemediationHost {
  host: string; os: string | null; platform: Platform; online: boolean; lastSeenH: number | null; isPilot: boolean;
}

function platformOf(system: string): Platform | null {
  const s = (system || '').toLowerCase();
  if (s.includes('windows')) return 'windows';
  if (s.includes('linux')) return 'linux';
  return null; // macOS u otros: no soportado por ahora
}

/** Hosts Windows/Linux candidatos a remediación (de-dup por host, liveness real de Velo). */
export async function listRemediationHosts(): Promise<RemediationHost[]> {
  const raw = await runHelper(['list']);
  if (!Array.isArray(raw)) throw new Error(raw?.error || 'Velociraptor no disponible');
  const now = Date.now();
  const byHost = new Map<string, any>();
  for (const c of raw) {
    if (!platformOf(String(c?.system || ''))) continue; // solo Windows/Linux
    const host = String(c?.host || '');
    if (!host) continue;
    const prev = byHost.get(host.toLowerCase());
    if (!prev || (c.last_seen_at ?? 0) > (prev.last_seen_at ?? 0)) byHost.set(host.toLowerCase(), c);
  }
  const out = [...byHost.values()].map((c) => {
    const ms = c.last_seen_at ? c.last_seen_at / 1000 : 0;
    const lastSeenH = ms ? (now - ms) / 3_600_000 : null;
    return {
      host: String(c.host), os: c.release || c.system || null,
      platform: platformOf(String(c.system || '')) as Platform,
      online: lastSeenH !== null && lastSeenH <= 24,
      lastSeenH: lastSeenH === null ? null : Math.round(lastSeenH * 10) / 10,
      isPilot: isPilotHost(String(c.host)),
    };
  });
  out.sort((a, b) => Number(b.online) - Number(a.online) || Number(b.isPilot) - Number(a.isPilot) || a.host.localeCompare(b.host));
  return out;
}

async function resolvePlatform(host: string): Promise<Platform | null> {
  const hosts = await listRemediationHosts();
  return hosts.find((h) => h.host.toLowerCase() === host.toLowerCase())?.platform ?? null;
}

export interface RemediationJob {
  id: string; host: string; client_id: string; flow_id: string | null;
  kind: 'scan' | 'apply' | 'auto'; platform: Platform; package: string | null;
  status: 'running' | 'done' | 'error';
  exit_code: number | null; reboot: boolean | null; packages: unknown; output: string | null; error: string | null;
  actor_email: string | null; created_at: string; finished_at: string | null;
}

async function insertJob(j: Partial<RemediationJob>): Promise<RemediationJob> {
  const id = randomUUID();
  const rows = await query<RemediationJob>(
    `INSERT INTO remediation_jobs (id, host, client_id, flow_id, kind, platform, package, status, actor_email)
     VALUES ($1,$2,$3,$4,$5,$6,$7,'running',$8) RETURNING *`,
    [id, j.host, j.client_id, j.flow_id ?? null, j.kind, j.platform ?? 'windows', j.package ?? null, j.actor_email ?? null]
  );
  return rows[0];
}

/** Lanza un escaneo (dry-run, sólo lectura). Windows: winget upgrade; Linux: apt (solo lista). */
export async function startScan(host: string, actorEmail: string): Promise<RemediationJob> {
  if (!HOST_RE.test(host)) throw new Error('host inválido');
  const platform = await resolvePlatform(host);
  if (!platform) throw new Error('host no soportado (solo Windows/Linux) o sin agente Velociraptor.');
  const r = await runHelper([platform === 'linux' ? 'apt_scan' : 'winget_list', host]);
  if (r?.error) throw new Error(r.error);
  if (!r?.flow_id) throw new Error('No se pudo lanzar el escaneo en el endpoint (¿agente en línea?).');
  return insertJob({ host, client_id: r.client_id, flow_id: r.flow_id, kind: 'scan', platform, actor_email: actorEmail });
}

/**
 * Lanza una aplicación. Sólo hosts piloto.
 * Windows: actualiza el paquete winget indicado (packageId).
 * Linux: aplica SOLO parches de seguridad (apt); packageId se ignora. Nunca reinicia.
 */
export async function startApply(host: string, packageId: string, actorEmail: string): Promise<RemediationJob> {
  if (!HOST_RE.test(host)) throw new Error('host inválido');
  if (!isPilotHost(host)) throw new Error(`"${host}" no es un equipo piloto. La aplicación está restringida a: ${PILOT_HOSTS.join(', ') || '(ninguno)'}.`);
  const platform = await resolvePlatform(host);
  if (!platform) throw new Error('host no soportado (solo Windows/Linux) o sin agente Velociraptor.');
  let r: any;
  if (platform === 'linux') {
    r = await runHelper(['apt_apply', host]); // solo-seguridad
  } else {
    if (!PKG_RE.test(packageId)) throw new Error('paquete inválido');
    r = await runHelper(['winget_apply', host, packageId]);
  }
  if (r?.error) throw new Error(r.error);
  if (!r?.flow_id) throw new Error('No se pudo lanzar la actualización en el endpoint (¿agente en línea?).');
  return insertJob({ host, client_id: r.client_id, flow_id: r.flow_id, kind: 'apply', platform, package: platform === 'linux' ? 'seguridad' : packageId, actor_email: actorEmail });
}

/** Activa la automatización nativa de parches de SEGURIDAD (unattended-upgrades) en Linux. Sólo piloto. */
export async function startAutoEnable(host: string, actorEmail: string): Promise<RemediationJob> {
  if (!HOST_RE.test(host)) throw new Error('host inválido');
  if (!isPilotHost(host)) throw new Error(`"${host}" no es un equipo piloto. La automatización está restringida a: ${PILOT_HOSTS.join(', ') || '(ninguno)'}.`);
  const platform = await resolvePlatform(host);
  if (platform !== 'linux') throw new Error('La automatización nativa (unattended-upgrades) solo aplica a Linux.');
  const r = await runHelper(['apt_autoenable', host]);
  if (r?.error) throw new Error(r.error);
  if (!r?.flow_id) throw new Error('No se pudo lanzar la automatización en el endpoint (¿agente en línea?).');
  return insertJob({ host, client_id: r.client_id, flow_id: r.flow_id, kind: 'auto', platform, actor_email: actorEmail });
}

/** Cancela la sesión PowerShell del flow (best-effort). */
async function cancelFlow(cid: string, fid: string): Promise<void> {
  try { await runHelper(['cancel', cid, fid]); } catch (e) { logger.warn({ e }, 'remediation: fallo al cancelar flow'); }
}

async function finish(id: string, patch: Partial<RemediationJob>): Promise<void> {
  await query(
    `UPDATE remediation_jobs SET status=$2, exit_code=$3, packages=$4, output=$5, error=$6, reboot=$7, finished_at=now() WHERE id=$1`,
    [id, patch.status, patch.exit_code ?? null, patch.packages ? JSON.stringify(patch.packages) : null, patch.output ?? null, patch.error ?? null, patch.reboot ?? null]
  );
}

/** Sondea un job en curso: lee stdout, y si terminó parsea, cierra la sesión y persiste. */
export async function refreshJob(job: RemediationJob): Promise<RemediationJob> {
  if (job.status !== 'running' || !job.flow_id) return job;
  const ageMin = (Date.now() - new Date(job.created_at).getTime()) / 60_000;

  let out = '';
  try {
    const r = await runHelper(['ps_output', job.client_id, job.flow_id]);
    out = String(r?.stdout || '');
  } catch (e) {
    logger.warn({ e }, 'remediation: fallo al leer salida');
  }

  if (isComplete(out)) {
    await cancelFlow(job.client_id, job.flow_id);
    if (job.platform === 'linux') {
      if (job.kind === 'scan') {
        const p = parseAptScan(out);
        await finish(job.id, p.ok
          ? { status: 'done', packages: p.packages, reboot: p.reboot, error: null }
          : { status: 'error', error: p.error || 'apt falló' });
      } else {
        const p = parseAptApply(out);
        const ok = p.exitCode === 0;
        await finish(job.id, {
          status: ok ? 'done' : 'error', exit_code: p.exitCode, output: p.clean, reboot: p.reboot,
          error: ok ? null : (p.error || `apt terminó con código ${p.exitCode}`),
        });
      }
    } else if (job.kind === 'scan') {
      const p = parseWingetList(out);
      await finish(job.id, p.ok
        ? { status: 'done', packages: p.packages, output: p.clean, error: null }
        : { status: 'error', error: p.error || 'winget falló', output: p.clean });
    } else {
      const p = parseWingetApply(out);
      const ok = p.exitCode === 0;
      await finish(job.id, {
        status: ok ? 'done' : 'error', exit_code: p.exitCode, output: p.clean,
        error: ok ? null : (p.error || `winget terminó con código ${p.exitCode}`),
      });
    }
  } else if (ageMin > JOB_MAX_MIN) {
    await cancelFlow(job.client_id, job.flow_id);
    await finish(job.id, { status: 'error', error: `Tiempo de espera agotado (${JOB_MAX_MIN} min) sin respuesta del endpoint.` });
  } else {
    return job; // sigue en curso
  }
  return getJob(job.id) as Promise<RemediationJob>;
}

export async function getJob(id: string): Promise<RemediationJob | null> {
  const rows = await query<RemediationJob>(`SELECT * FROM remediation_jobs WHERE id=$1`, [id]);
  const job = rows[0];
  if (!job) return null;
  return job.status === 'running' ? refreshJob(job) : job;
}

/** Últimos jobs (para el historial del panel). */
export async function recentJobs(limit = 20): Promise<RemediationJob[]> {
  return query<RemediationJob>(`SELECT * FROM remediation_jobs ORDER BY created_at DESC LIMIT $1`, [Math.min(limit, 100)]);
}

/**
 * Finalizador en segundo plano: cierra los jobs 'running' aunque nadie tenga el
 * panel abierto. Sin esto, un escaneo/aplicación que termina en el endpoint queda
 * 'running' para siempre en la BD si el navegador dejó de sondear (la detección de
 * fin solo corría en el GET /job/:id). Cada N segundos refresca los jobs en curso;
 * refreshJob lee la salida, y si terminó parsea + cancela la sesión + persiste, o
 * expira el job pasado el corte de seguridad.
 */
let sweeperStarted = false;
export function startRemediationSweeper(): void {
  if (sweeperStarted) return;
  sweeperStarted = true;
  const everyMs = Number(process.env.REMEDIATION_SWEEP_SECONDS || 30) * 1000;
  const tick = async (): Promise<void> => {
    try {
      const running = await query<RemediationJob>(`SELECT * FROM remediation_jobs WHERE status='running' ORDER BY created_at DESC LIMIT 20`);
      for (const j of running) {
        try { await refreshJob(j); } catch (e) { logger.warn({ e, job: j.id }, 'remediation sweeper: fallo al refrescar job'); }
      }
    } catch (e) {
      logger.warn({ e }, 'remediation sweeper: fallo al listar jobs en curso');
    }
  };
  const t = setInterval(() => { void tick(); }, everyMs);
  t.unref?.();
  logger.info({ everyMs }, 'remediation: finalizador en segundo plano activo');
}
