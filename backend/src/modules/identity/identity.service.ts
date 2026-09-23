/**
 * Respuesta de identidad (SOAR #7): deshabilitar cuentas comprometidas.
 *  - AD on-prem por LDAP: pone el bit ACCOUNTDISABLE en userAccountControl.
 *  - M365/Azure AD por Microsoft Graph: accountEnabled=false + revoca sesiones.
 *  - (Cuarentena de correo por Graph: quarantineSenderInMailbox — para #5.)
 *
 * Todo es INERTE hasta configurar credenciales (LDAP_* / GRAPH_*): sin ellas cada
 * función lanza HttpError 503 "no configurado", igual que el cliente de FortiGate.
 * El paquete `ldapts` se carga de forma diferida: no hace falta instalarlo hasta
 * que se use realmente el bloqueo de AD.
 */
import axios from 'axios';
import https from 'node:https';
import { env } from '../../config/env';
import { HttpError } from '../auth/auth.service';
import { getIndexerClient } from '../wazuh/wazuh.client';
import { geolocate, isPublicIP } from '../geo/geoip.service';

// ---------------------------------------------------------------------------
// Active Directory (LDAP)
// ---------------------------------------------------------------------------
export function isAdConfigured(): boolean {
  return Boolean(env.LDAP_URL && env.LDAP_BIND_DN && env.LDAP_BIND_PASSWORD && env.LDAP_BASE_DN);
}

const UAC_ACCOUNTDISABLE = 0x2;

/** Deshabilita una cuenta de AD (por sAMAccountName o el atributo configurado). */
export async function disableAdUser(identifier: string): Promise<{ dn: string }> {
  if (!isAdConfigured()) throw new HttpError(503, 'AD/LDAP no configurado (define LDAP_URL, LDAP_BIND_DN, LDAP_BIND_PASSWORD y LDAP_BASE_DN)');
  const user = identifier.replace(/^.*\\/, '').split('@')[0].trim(); // limpia DOMINIO\ y @dominio
  if (!user) throw new HttpError(400, 'Usuario inválido');

  // Carga diferida de ldapts (evita dependencia dura hasta que se use).
  const spec: string = 'ldapts';
  const mod = (await import(spec).catch(() => null)) as { Client: new (o: unknown) => LdapClient } | null;
  if (!mod) throw new HttpError(503, 'Falta el paquete ldapts en el servidor (npm install ldapts)');

  const client = new mod.Client({
    url: env.LDAP_URL!,
    tlsOptions: { rejectUnauthorized: env.LDAP_TLS_REJECT_UNAUTHORIZED },
    timeout: 10_000,
    connectTimeout: 10_000,
  });
  try {
    await client.bind(env.LDAP_BIND_DN!, env.LDAP_BIND_PASSWORD!);
    const attr = env.LDAP_USER_ATTR || 'sAMAccountName';
    const { searchEntries } = await client.search(env.LDAP_BASE_DN!, {
      scope: 'sub',
      filter: `(${attr}=${user})`,
      attributes: ['distinguishedName', 'userAccountControl'],
    });
    if (!searchEntries.length) throw new HttpError(404, `Cuenta AD no encontrada: ${user}`);
    const entry = searchEntries[0];
    const dn = String(entry.dn ?? entry.distinguishedName);
    const uac = Number(Array.isArray(entry.userAccountControl) ? entry.userAccountControl[0] : entry.userAccountControl) || 512;
    const newUac = uac | UAC_ACCOUNTDISABLE;
    const { Change, Attribute } = mod as unknown as { Change: new (o: unknown) => unknown; Attribute: new (o: unknown) => unknown };
    await client.modify(dn, new Change({ operation: 'replace', modification: new Attribute({ type: 'userAccountControl', values: [String(newUac)] }) }));
    return { dn };
  } finally {
    await client.unbind().catch(() => undefined);
  }
}

interface LdapClient {
  bind(dn: string, pw: string): Promise<void>;
  search(base: string, opts: unknown): Promise<{ searchEntries: Record<string, unknown>[] }>;
  modify(dn: string, change: unknown): Promise<void>;
  unbind(): Promise<void>;
}

// ---------------------------------------------------------------------------
// Microsoft Graph (M365 / Azure AD)
// ---------------------------------------------------------------------------
export function isGraphConfigured(): boolean {
  return Boolean(env.GRAPH_TENANT_ID && env.GRAPH_CLIENT_ID && env.GRAPH_CLIENT_SECRET);
}

let tokenCache: { token: string; exp: number } | null = null;

async function graphToken(): Promise<string> {
  if (tokenCache && Date.now() < tokenCache.exp) return tokenCache.token;
  const body = new URLSearchParams({
    client_id: env.GRAPH_CLIENT_ID!,
    client_secret: env.GRAPH_CLIENT_SECRET!,
    scope: 'https://graph.microsoft.com/.default',
    grant_type: 'client_credentials',
  });
  const { data } = await axios.post<{ access_token: string; expires_in: number }>(
    `https://login.microsoftonline.com/${env.GRAPH_TENANT_ID}/oauth2/v2.0/token`,
    body.toString(),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 12_000 },
  );
  tokenCache = { token: data.access_token, exp: Date.now() + (data.expires_in - 60) * 1000 };
  return data.access_token;
}

function graph() {
  return axios.create({
    baseURL: 'https://graph.microsoft.com/v1.0',
    timeout: 15_000,
    httpsAgent: new https.Agent({ keepAlive: true }),
  });
}

/** Deshabilita la cuenta en Azure AD y revoca sus sesiones activas. */
export async function disableM365User(upn: string): Promise<{ upn: string; revoked: boolean }> {
  if (!isGraphConfigured()) throw new HttpError(503, 'Microsoft Graph no configurado (define GRAPH_TENANT_ID, GRAPH_CLIENT_ID y GRAPH_CLIENT_SECRET)');
  const u = upn.trim();
  if (!u.includes('@')) throw new HttpError(400, 'Se requiere el UPN (correo) del usuario para M365');
  try {
    const token = await graphToken();
    const h = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };
    await graph().patch(`/users/${encodeURIComponent(u)}`, { accountEnabled: false }, { headers: h });
    let revoked = false;
    try { await graph().post(`/users/${encodeURIComponent(u)}/revokeSignInSessions`, {}, { headers: h }); revoked = true; } catch { /* opcional */ }
    return { upn: u, revoked };
  } catch (err) {
    mapGraphError(err, 'deshabilitar M365');
  }
}

/** Cuarentena básica: mueve a Deleted Items los correos de un remitente en un buzón. (#5) */
export async function quarantineSenderInMailbox(mailbox: string, sender: string): Promise<{ moved: number }> {
  if (!isGraphConfigured()) throw new HttpError(503, 'Microsoft Graph no configurado');
  try {
    const token = await graphToken();
    const h = { Authorization: `Bearer ${token}` };
    const { data } = await graph().get<{ value: { id: string }[] }>(
      `/users/${encodeURIComponent(mailbox)}/messages?$filter=${encodeURIComponent(`from/emailAddress/address eq '${sender}'`)}&$top=50&$select=id`,
      { headers: h },
    );
    let moved = 0;
    for (const m of data.value ?? []) {
      await graph().post(`/users/${encodeURIComponent(mailbox)}/messages/${m.id}/move`, { destinationId: 'deleteditems' }, { headers: { ...h, 'Content-Type': 'application/json' } }).then(() => { moved++; }).catch(() => undefined);
    }
    return { moved };
  } catch (err) {
    mapGraphError(err, 'cuarentena de correo');
  }
}

// ---------------------------------------------------------------------------
// Directorio M365 (SOLO LECTURA) — alimenta el panel de Identidades en HexWatch.
// ---------------------------------------------------------------------------
interface RawUser { displayName?: string; userPrincipalName?: string; accountEnabled?: boolean; userType?: string; createdDateTime?: string; mail?: string; externalUserState?: string }
export interface M365Identity { displayName: string; upn: string; enabled: boolean; guest: boolean; created: string | null }
export interface M365Directory {
  configured: boolean;
  total: number; enabled: number; disabled: number; guests: number;
  truncated: boolean;
  recent: M365Identity[];
  disabledList: M365Identity[];
  guestList: M365Identity[];
  generatedAt: string;
}

/** Lista usuarios del tenant (Graph GET /users, solo lectura) y arma un resumen. */
export async function listM365Identities(): Promise<M365Directory> {
  const base = (configured: boolean): M365Directory => ({
    configured, total: 0, enabled: 0, disabled: 0, guests: 0, truncated: false,
    recent: [], disabledList: [], guestList: [], generatedAt: new Date().toISOString(),
  });
  if (!isGraphConfigured()) return base(false);
  try {
    const token = await graphToken();
    const { data } = await graph().get<{ value?: RawUser[]; '@odata.nextLink'?: string }>(
      '/users?$select=displayName,userPrincipalName,accountEnabled,userType,createdDateTime&$top=999',
      { headers: { Authorization: `Bearer ${token}`, ConsistencyLevel: 'eventual' } },
    );
    const users: M365Identity[] = (data.value ?? []).map((u) => ({
      displayName: u.displayName || '(sin nombre)',
      upn: u.userPrincipalName || '',
      enabled: Boolean(u.accountEnabled),
      guest: u.userType === 'Guest',
      created: u.createdDateTime ?? null,
    }));
    const recent = [...users].sort((a, b) => (b.created || '').localeCompare(a.created || ''));
    return {
      configured: true,
      total: users.length,
      enabled: users.filter((u) => u.enabled).length,
      disabled: users.filter((u) => !u.enabled).length,
      guests: users.filter((u) => u.guest).length,
      truncated: Boolean(data['@odata.nextLink']),
      recent: recent.slice(0, 10),
      disabledList: users.filter((u) => !u.enabled).slice(0, 25),
      guestList: users.filter((u) => u.guest).slice(0, 25),
      generatedAt: new Date().toISOString(),
    };
  } catch (err) {
    mapGraphError(err, 'listar identidades M365');
  }
}

/** Elimina una cuenta del tenant (Graph DELETE /users). Destructivo — solo admin. */
export async function deleteM365User(upn: string): Promise<{ upn: string; deleted: true }> {
  if (!isGraphConfigured()) throw new HttpError(503, 'Microsoft Graph no configurado');
  const u = upn.trim();
  if (!u) throw new HttpError(400, 'Se requiere el UPN del usuario');
  try {
    const token = await graphToken();
    await graph().delete(`/users/${encodeURIComponent(u)}`, { headers: { Authorization: `Bearer ${token}` } });
    return { upn: u, deleted: true };
  } catch (err) {
    mapGraphError(err, 'eliminar usuario M365');
  }
}

// ---------------------------------------------------------------------------
// Recomendaciones de higiene de identidad (invitados externos) — SOLO LECTURA.
// Cruza Graph (guests + grupos) con la actividad real de auditoría O365 (indexer)
// y produce un veredicto accionable por invitado.
// ---------------------------------------------------------------------------
const PERSONAL_DOMAINS = ['gmail.com', 'hotmail.com', 'outlook.com', 'yahoo.com', 'yahoo.es', 'live.com', 'icloud.com', 'protonmail.com'];

export type RecSeverity = 'alta' | 'media' | 'baja';
export interface IdentityRec {
  kind: 'guest' | 'signin';
  upn: string; displayName: string; mail: string; enabled: boolean;
  severity: RecSeverity; title: string; reason: string;
  meta: { label: string; value: string }[];
  actions: string[];
}

interface IdxSearch { hits: { total: { value: number } | number }; aggregations?: { last?: { value_as_string?: string } } }
interface TermBucket { key: string; doc_count: number }
interface SignInUserBucket { key: string; doc_count: number; fail: { doc_count: number }; ok: { doc_count: number; ips: { buckets: TermBucket[] } }; last: { value_as_string?: string } }
interface SignInAgg { aggregations?: { users?: { buckets: SignInUserBucket[] } } }

export async function getIdentityRecommendations(): Promise<{ configured: boolean; generatedAt: string; items: IdentityRec[] }> {
  const out = (configured: boolean, items: IdentityRec[] = []) => ({ configured, generatedAt: new Date().toISOString(), items });
  if (!isGraphConfigured()) return out(false);

  const token = await graphToken();
  const gh = { Authorization: `Bearer ${token}`, ConsistencyLevel: 'eventual' };
  const sel = 'displayName,userPrincipalName,mail,externalUserState,createdDateTime,accountEnabled';
  let guests: RawUser[];
  try {
    const { data } = await graph().get<{ value?: RawUser[] }>(
      `/users?$filter=${encodeURIComponent("userType eq 'Guest'")}&$select=${sel}&$top=100`, { headers: gh });
    guests = data.value ?? [];
  } catch (err) {
    mapGraphError(err, 'listar invitados M365');
  }

  const idx = getIndexerClient();
  const now = Date.now();
  const items: IdentityRec[] = [];

  for (const u of guests) {
    const upn = u.userPrincipalName ?? '';
    const mail = u.mail ?? '';
    const created = u.createdDateTime ?? null;
    const ageDays = created ? Math.floor((now - new Date(created).getTime()) / 86_400_000) : null;
    const state = u.externalUserState ?? 'Desconocido';
    const enabled = Boolean(u.accountEnabled);

    // Grupos/equipos (puede no ser accesible sin GroupMember.Read.All).
    let groups: number | null = null;
    try {
      const { data: mo } = await graph().get<{ value?: unknown[] }>(`/users/${encodeURIComponent(upn)}/memberOf?$select=id`, { headers: gh });
      groups = (mo.value ?? []).length;
    } catch { groups = null; }

    // Actividad real en auditoría O365 (por mail y UPN), últimos 30 días.
    let activity30d = 0; let lastActivity: string | null = null;
    try {
      const ids = [mail, upn].filter(Boolean);
      const { data: r } = await idx.post<IdxSearch>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
        size: 0, track_total_hits: true,
        query: { bool: { filter: [{ range: { '@timestamp': { gte: 'now-30d' } } }, { terms: { 'data.office365.UserId': ids } }] } },
        aggs: { last: { max: { field: '@timestamp' } } },
      });
      const t = r.hits.total; activity30d = typeof t === 'number' ? t : t.value;
      lastActivity = r.aggregations?.last?.value_as_string ?? null;
    } catch { /* indexer opcional */ }

    const domain = (mail.split('@')[1] || '').toLowerCase();
    const personalEmail = PERSONAL_DOMAINS.includes(domain);
    const system = domain.endsWith('teams.mail.microsoft') || upn.toLowerCase().startsWith('no-reply');
    const noGroups = (groups ?? 0) === 0;

    let severity: RecSeverity = 'baja';
    let title = 'Invitado activo';
    let reason = '';
    let actions: string[] = ['disable'];

    if (system) {
      severity = 'baja'; title = 'Artefacto de Teams';
      reason = 'Identidad de sistema creada por Teams al invitar externos a una reunión. Inofensiva; se puede eliminar para limpiar el directorio.';
      actions = ['delete'];
    } else if (state === 'PendingAcceptance' && (ageDays ?? 0) > 30 && activity30d === 0 && noGroups) {
      severity = 'alta'; title = 'Invitación pendiente sin aceptar — eliminar';
      reason = `Invitada hace ${ageDays} días y nunca aceptó (${state}). Sin grupos ni actividad: identidad externa muerta que solo suma superficie de ataque.${personalEmail ? ' Correo personal.' : ''}`;
      actions = ['delete', 'disable'];
    } else if (activity30d === 0 && noGroups) {
      severity = 'media'; title = 'Invitado sin uso — revisar';
      reason = `${state === 'Accepted' ? 'Aceptó la invitación pero' : 'Estado ' + state + ';'} no tiene grupos ni actividad en 30 días. Validar con negocio si sigue siendo necesario.${personalEmail ? ' Correo personal.' : ''}`;
      actions = ['disable', 'delete'];
    } else if (activity30d > 0) {
      severity = 'baja'; title = 'Invitado activo';
      reason = `${activity30d} eventos en 30 días (último ${(lastActivity || '').slice(0, 10)}). En uso.`;
      actions = ['disable'];
    } else {
      severity = 'media'; title = 'Invitado sin actividad reciente';
      reason = `Sin actividad en 30 días.${personalEmail ? ' Correo personal.' : ''}`;
      actions = ['disable', 'delete'];
    }

    const meta = [
      { label: 'estado', value: state },
      { label: 'edad', value: ageDays != null ? `${ageDays}d` : 's/d' },
      { label: 'grupos', value: groups != null ? String(groups) : 's/d' },
      { label: 'actividad 30d', value: String(activity30d) },
      { label: 'cuenta', value: enabled ? 'habilitada' : 'deshabilitada' },
    ];
    items.push({ kind: 'guest', upn, displayName: u.displayName || '(sin nombre)', mail, enabled, severity, title, reason, meta, actions });
  }

  // ---------- Amenazas de identidad por sign-ins O365 (últimos 7 días) ----------
  // Fuerza bruta (muchos fallidos) y/o sign-in EXITOSO desde país inusual (fuera CO).
  try {
    const { data: si } = await idx.post<SignInAgg>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
      size: 0,
      query: { bool: { filter: [
        { range: { '@timestamp': { gte: 'now-7d' } } },
        { terms: { 'data.office365.Operation': ['UserLoggedIn', 'UserLoginFailed'] } },
      ] } },
      aggs: { users: { terms: { field: 'data.office365.UserId', size: 80 }, aggs: {
        fail: { filter: { term: { 'data.office365.Operation': 'UserLoginFailed' } } },
        ok: { filter: { term: { 'data.office365.Operation': 'UserLoggedIn' } },
          aggs: { ips: { terms: { field: 'data.office365.ActorIpAddress', size: 12 } } } },
        last: { max: { field: '@timestamp' } },
      } } },
    });
    for (const b of si.aggregations?.users?.buckets ?? []) {
      const upn = b.key;
      if (!upn.includes('@') || upn.startsWith('urn:')) continue; // salta identidades de sistema
      const failed = b.fail.doc_count; const ok = b.ok.doc_count;
      const countries = new Set<string>();
      let foreignSuccessIps = 0;
      for (const ib of b.ok.ips.buckets ?? []) {
        if (!isPublicIP(ib.key)) continue;
        const g = geolocate(ib.key);
        if (g?.country) {
          countries.add(g.country);
          if (g.isoCode && g.isoCode !== 'CO') foreignSuccessIps += 1;
        }
      }
      const foreignCountries = [...countries].filter((c) => c !== 'Colombia');
      const bruteForce = failed >= 15;
      const foreignSuccess = ok > 0 && foreignCountries.length > 0 && foreignSuccessIps > 0;
      if (!bruteForce && !foreignSuccess) continue;

      const meta = [
        { label: 'fallidos 7d', value: String(failed) },
        { label: 'exitosos 7d', value: String(ok) },
        { label: 'IPs de inicio', value: String((b.ok.ips.buckets ?? []).length) },
        { label: 'países', value: [...countries].join(' / ') || '—' },
      ];
      if (foreignSuccess) {
        items.push({ kind: 'signin', upn, displayName: upn.split('@')[0], mail: upn, enabled: true,
          severity: 'alta', title: 'Sign-in exitoso desde país inusual',
          reason: `Inició sesión con éxito desde ${foreignCountries.join(', ')} (fuera de Colombia) en los últimos 7 días. Posible cuenta comprometida — contener y verificar con la persona.`,
          meta, actions: ['disable'] });
      } else {
        items.push({ kind: 'signin', upn, displayName: upn.split('@')[0], mail: upn, enabled: true,
          severity: 'media', title: 'Posible ataque de credenciales',
          reason: `${failed} inicios de sesión fallidos en 7 días (posible fuerza bruta / password spray). Revisar y, si procede, forzar cambio de contraseña o contener.`,
          meta, actions: [] });
      }
    }
  } catch { /* sin datos de sign-in: se omite */ }

  const rank: Record<RecSeverity, number> = { alta: 0, media: 1, baja: 2 };
  items.sort((a, b) => rank[a.severity] - rank[b.severity]);
  return out(true, items);
}

function mapGraphError(err: unknown, ctx: string): never {
  if (err instanceof HttpError) throw err;
  const e = err as { response?: { status: number; data?: { error?: { message?: string } } } };
  if (e.response?.status === 401 || e.response?.status === 403) throw new HttpError(502, `Graph rechazó permisos (${ctx}). Revisa los permisos de la app (User.ReadWrite.All / Mail.ReadWrite).`);
  throw new HttpError(502, `Error en Microsoft Graph (${ctx}): ${e.response?.data?.error?.message ?? 'desconocido'}`);
}
