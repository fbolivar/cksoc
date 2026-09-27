/**
 * EDR / NGAV — conector a la plataforma de protección de endpoint del cliente.
 * NO construimos AV: integramos y consumimos la telemetría de un EDR/NGAV
 * (SentinelOne o Microsoft Defender for Endpoint) y exponemos sus acciones de
 * respuesta (aislar, escanear) desde HexWatch. Es INERTE hasta configurar
 * credenciales del cliente (modo on-demand, como los conectores de nube/MISP).
 *
 * Proveedores:
 *   - SentinelOne: S1_URL + S1_TOKEN (API token de gestión).
 *   - Defender (MDE): MDE_TENANT_ID + MDE_CLIENT_ID + MDE_CLIENT_SECRET
 *     (app propia con permisos WindowsDefenderATP: Alert.Read.All, Machine.*).
 */
import { env } from '../../config/env';
import { logger } from '../../config/logger';
import { HttpError } from '../auth/auth.service';

export type EdrProvider = 'sentinelone' | 'defender' | 'none';
export type Sev = 'critica' | 'alta' | 'media' | 'baja' | 'info';

export interface EdrAlert { id: string; title: string; severity: Sev; category: string; device: string; user: string | null; status: string; createdAt: string; }
export interface EdrDevice { id: string; name: string; os: string; health: string; isolated: boolean; riskLevel: string; lastSeen: string; }
export interface EdrStatus { provider: EdrProvider; configured: boolean; reachable: boolean; error: string | null; }

const S1_URL = (env.S1_URL || '').replace(/\/+$/, '');
const S1_TOKEN = env.S1_TOKEN || '';
const MDE_TENANT = env.MDE_TENANT_ID || '';
const MDE_CLIENT = env.MDE_CLIENT_ID || '';
const MDE_SECRET = env.MDE_CLIENT_SECRET || '';
const MDE_BASE = (env.MDE_API_BASE || 'https://api.securitycenter.microsoft.com').replace(/\/+$/, '');

export function provider(): EdrProvider {
  const forced = (env.EDR_PROVIDER || '').toLowerCase();
  if (forced === 'sentinelone' || forced === 'defender') return forced;
  if (S1_URL && S1_TOKEN) return 'sentinelone';
  if (MDE_TENANT && MDE_CLIENT && MDE_SECRET) return 'defender';
  return 'none';
}
export function isConfigured(): boolean { return provider() !== 'none'; }

async function fetchJson<T>(url: string, opts: RequestInit = {}, timeoutMs = 20000): Promise<{ status: number; data: T }> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(url, { ...opts, signal: ctrl.signal });
    let data: unknown = {}; try { data = await r.json(); } catch { /* vacío */ }
    return { status: r.status, data: data as T };
  } finally { clearTimeout(t); }
}

// ---------- SentinelOne ----------
const s1h = { Authorization: `ApiToken ${S1_TOKEN}`, 'Content-Type': 'application/json' };
function s1sev(v: string | undefined, verdict: string | undefined): Sev {
  const c = String(v || '').toLowerCase(); const a = String(verdict || '').toLowerCase();
  if (a.includes('true_positive') || c === 'malicious') return 'critica';
  if (c === 'suspicious' || a.includes('suspicious')) return 'alta';
  return 'media';
}
interface S1Threat { id: string; threatInfo?: { threatName?: string; classification?: string; confidenceLevel?: string; analystVerdict?: string; mitigationStatus?: string; identifiedAt?: string; createdAt?: string }; agentRealtimeInfo?: { agentComputerName?: string } }
interface S1Agent { id: string; computerName?: string; osName?: string; networkStatus?: string; lastActiveDate?: string; infected?: boolean; isUpToDate?: boolean; isActive?: boolean }

async function s1Alerts(): Promise<EdrAlert[]> {
  const { status, data } = await fetchJson<{ data?: S1Threat[] }>(`${S1_URL}/web/api/v2.1/threats?limit=50&sortBy=createdAt&sortOrder=desc`, { headers: s1h });
  if (status !== 200) throw new HttpError(status, `SentinelOne respondió HTTP ${status}`);
  return (data.data ?? []).map((t) => ({
    id: t.id, title: t.threatInfo?.threatName ?? 'Amenaza', severity: s1sev(t.threatInfo?.confidenceLevel, t.threatInfo?.analystVerdict),
    category: t.threatInfo?.classification ?? '', device: t.agentRealtimeInfo?.agentComputerName ?? '', user: null,
    status: t.threatInfo?.mitigationStatus ?? '', createdAt: t.threatInfo?.identifiedAt ?? t.threatInfo?.createdAt ?? '',
  }));
}
async function s1Devices(): Promise<EdrDevice[]> {
  const { status, data } = await fetchJson<{ data?: S1Agent[] }>(`${S1_URL}/web/api/v2.1/agents?limit=200`, { headers: s1h });
  if (status !== 200) throw new HttpError(status, `SentinelOne respondió HTTP ${status}`);
  return (data.data ?? []).map((a) => ({
    id: a.id, name: a.computerName ?? '', os: a.osName ?? '',
    health: a.infected ? 'infectado' : (a.isActive ? 'activo' : 'inactivo'),
    isolated: String(a.networkStatus || '').toLowerCase() === 'disconnected',
    riskLevel: a.infected ? 'alto' : (a.isUpToDate ? 'ok' : 'desactualizado'), lastSeen: a.lastActiveDate ?? '',
  }));
}
async function s1Action(path: string, deviceId: string): Promise<void> {
  const { status } = await fetchJson(`${S1_URL}/web/api/v2.1/agents/actions/${path}`, { method: 'POST', headers: s1h, body: JSON.stringify({ filter: { ids: [deviceId] } }) });
  if (status >= 300) throw new HttpError(status, `SentinelOne acción HTTP ${status}`);
}

// ---------- Microsoft Defender (MDE) ----------
let mdeTok: { t: string; exp: number } | null = null;
async function mdeToken(): Promise<string> {
  if (mdeTok && Date.now() < mdeTok.exp) return mdeTok.t;
  const body = new URLSearchParams({ grant_type: 'client_credentials', client_id: MDE_CLIENT, client_secret: MDE_SECRET, resource: MDE_BASE });
  const { status, data } = await fetchJson<{ access_token?: string; expires_in?: number }>(`https://login.microsoftonline.com/${MDE_TENANT}/oauth2/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString() });
  if (status !== 200 || !data.access_token) throw new HttpError(503, 'MDE: no se pudo autenticar (revisar permisos WindowsDefenderATP)');
  mdeTok = { t: data.access_token, exp: Date.now() + (data.expires_in ?? 3600) * 1000 - 60_000 };
  return mdeTok.t;
}
function mdeSev(s: string | undefined): Sev {
  switch (String(s || '').toLowerCase()) { case 'high': return 'alta'; case 'medium': return 'media'; case 'low': return 'baja'; case 'informational': return 'info'; default: return 'media'; }
}
interface MdeAlert { id: string; title?: string; severity?: string; category?: string; computerDnsName?: string; relatedUser?: { userName?: string }; status?: string; alertCreationTime?: string }
interface MdeMachine { id: string; computerDnsName?: string; osPlatform?: string; healthStatus?: string; riskScore?: string; lastSeen?: string; }

async function mdeGet<T>(path: string): Promise<{ status: number; data: T }> {
  return fetchJson<T>(`${MDE_BASE}${path}`, { headers: { Authorization: `Bearer ${await mdeToken()}` } });
}
async function mdeAlerts(): Promise<EdrAlert[]> {
  const { status, data } = await mdeGet<{ value?: MdeAlert[] }>('/api/alerts?$top=50&$orderby=alertCreationTime%20desc');
  if (status !== 200) throw new HttpError(status, `MDE respondió HTTP ${status}`);
  return (data.value ?? []).map((a) => ({
    id: a.id, title: a.title ?? 'Alerta', severity: mdeSev(a.severity), category: a.category ?? '',
    device: a.computerDnsName ?? '', user: a.relatedUser?.userName ?? null, status: a.status ?? '', createdAt: a.alertCreationTime ?? '',
  }));
}
async function mdeDevices(): Promise<EdrDevice[]> {
  const { status, data } = await mdeGet<{ value?: MdeMachine[] }>('/api/machines?$top=200');
  if (status !== 200) throw new HttpError(status, `MDE respondió HTTP ${status}`);
  return (data.value ?? []).map((m) => ({
    id: m.id, name: m.computerDnsName ?? '', os: m.osPlatform ?? '', health: m.healthStatus ?? '',
    isolated: false, riskLevel: String(m.riskScore ?? '').toLowerCase() || 'ok', lastSeen: m.lastSeen ?? '',
  }));
}
async function mdePost(path: string, bodyObj: unknown): Promise<void> {
  const { status } = await fetchJson(`${MDE_BASE}${path}`, { method: 'POST', headers: { Authorization: `Bearer ${await mdeToken()}`, 'Content-Type': 'application/json' }, body: JSON.stringify(bodyObj) });
  if (status >= 300) throw new HttpError(status, `MDE acción HTTP ${status}`);
}

// ---------- API pública (agnóstica de proveedor) ----------
export async function getStatus(): Promise<EdrStatus> {
  const p = provider();
  if (p === 'none') return { provider: 'none', configured: false, reachable: false, error: null };
  try {
    if (p === 'sentinelone') { const { status } = await fetchJson(`${S1_URL}/web/api/v2.1/system/status`, { headers: s1h }); return { provider: p, configured: true, reachable: status === 200, error: status === 200 ? null : `HTTP ${status}` }; }
    await mdeToken(); return { provider: p, configured: true, reachable: true, error: null };
  } catch (e) { return { provider: p, configured: true, reachable: false, error: e instanceof Error ? e.message : 'error' }; }
}
function ensure(): EdrProvider { const p = provider(); if (p === 'none') throw new HttpError(503, 'EDR no configurado (define S1_URL/S1_TOKEN o MDE_*). Conector a demanda.'); return p; }

export async function getAlerts(): Promise<EdrAlert[]> { return ensure() === 'sentinelone' ? s1Alerts() : mdeAlerts(); }
export async function getDevices(): Promise<EdrDevice[]> { return ensure() === 'sentinelone' ? s1Devices() : mdeDevices(); }
export async function isolate(id: string): Promise<void> {
  if (ensure() === 'sentinelone') return s1Action('disconnect', id);
  return mdePost(`/api/machines/${encodeURIComponent(id)}/isolate`, { Comment: 'Aislado desde HexWatch', IsolationType: 'Full' });
}
export async function unisolate(id: string): Promise<void> {
  if (ensure() === 'sentinelone') return s1Action('connect', id);
  return mdePost(`/api/machines/${encodeURIComponent(id)}/unisolate`, { Comment: 'Reconectado desde HexWatch' });
}
export async function scan(id: string): Promise<void> {
  if (ensure() === 'sentinelone') return s1Action('initiate-scan', id);
  return mdePost(`/api/machines/${encodeURIComponent(id)}/runAntiVirusScan`, { Comment: 'Escaneo desde HexWatch', ScanType: 'Quick' });
}

export async function getOverview(): Promise<unknown> {
  const st = await getStatus();
  if (!st.configured || !st.reachable) return { status: st, alerts: [], devices: [], kpis: { alertas: 0, criticas: 0, dispositivos: 0, aislados: 0, enRiesgo: 0 } };
  const [alerts, devices] = await Promise.all([getAlerts().catch(() => [] as EdrAlert[]), getDevices().catch(() => [] as EdrDevice[])]);
  const kpis = {
    alertas: alerts.length,
    criticas: alerts.filter((a) => a.severity === 'critica' || a.severity === 'alta').length,
    dispositivos: devices.length,
    aislados: devices.filter((d) => d.isolated).length,
    enRiesgo: devices.filter((d) => d.health === 'infectado' || ['high', 'alto', 'medium'].includes(String(d.riskLevel).toLowerCase())).length,
  };
  logger.info({ provider: st.provider, alerts: alerts.length, devices: devices.length }, 'EDR: overview');
  return { status: st, alerts, devices, kpis };
}
