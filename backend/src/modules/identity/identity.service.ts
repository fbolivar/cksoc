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

function mapGraphError(err: unknown, ctx: string): never {
  if (err instanceof HttpError) throw err;
  const e = err as { response?: { status: number; data?: { error?: { message?: string } } } };
  if (e.response?.status === 401 || e.response?.status === 403) throw new HttpError(502, `Graph rechazó permisos (${ctx}). Revisa los permisos de la app (User.ReadWrite.All / Mail.ReadWrite).`);
  throw new HttpError(502, `Error en Microsoft Graph (${ctx}): ${e.response?.data?.error?.message ?? 'desconocido'}`);
}
