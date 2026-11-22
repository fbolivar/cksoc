/**
 * Cumplimiento normativo. Agrega las alertas de seguridad mapeadas a controles de:
 *  - Marcos NATIVOS que Wazuh etiqueta en cada alerta: NIST 800-53, GDPR, TSC (SOC 2),
 *    PCI DSS e HIPAA.
 *  - Marcos DERIVADOS por crosswalk (Wazuh NO los etiqueta): ISO/IEC 27001:2022 (Anexo A)
 *    y Ley 1581 de 2012 / Decreto 1074 (Habeas Data, Colombia). Se construyen sobre los
 *    controles técnicos de NIST y GDPR. Cubren la capa TÉCNICA; la parte legal/organizacional
 *    (registro RNBD, autorizaciones, política de tratamiento) es de gestión y no se ve en logs.
 *
 * Esto mide COBERTURA DE MONITOREO, no es un puntaje de cumplimiento. La postura de
 * configuración real se mide en Hardening CIS (SCA).
 */
import { getIndexerClient } from '../wazuh/wazuh.client';
import { env } from '../../config/env';
import { HttpError } from '../auth/auth.service';

const FIELDS: Record<string, string> = {
  nist: 'rule.nist_800_53',
  gdpr: 'rule.gdpr',
  tsc: 'rule.tsc',
  pci: 'rule.pci_dss',
  hipaa: 'rule.hipaa',
};

export interface Control { id: string; count: number; level: number; src?: string }
export interface FrameworkResult {
  total: number;              // alertas de SEGURIDAD (sin ruido) mapeadas al marco
  controlesCubiertos: number; // controles distintos con monitoreo (cobertura)
  controles: Control[];
  derivado?: boolean;         // true si el marco se construye por crosswalk (ISO/Ley 1581)
}
export type ComplianceData = { hours: number; frameworks: Record<string, FrameworkResult> };

// Ruido benigno de alto volumen que ahoga los mapeos de cumplimiento (el mismo
// que en los demás módulos). Sin esto, "revisión de logs/auditoría" (AU.6, PCI
// 10.6.1, HIPAA 164.312.b) suma ~900k de tráfico benigno y el conteo miente.
const COMPLIANCE_NOISE = [
  { terms: { 'rule.id': ['81633', '80792', '550', '752', '91578', '100205', '100207', '100700', '5501'] } },
  { terms: { 'rule.groups': ['sca', 'vulnerability-detector'] } },
  { bool: { filter: [{ term: { 'rule.id': '100600' } }, { bool: { should: [{ prefix: { 'data.dstip': '192.168.' } }, { prefix: { 'data.dstip': '10.' } }, { prefix: { 'data.dstip': '172.' } }], minimum_should_match: 1 } }] } },
];

// ---- Crosswalk NIST 800-53 -> ISO/IEC 27001:2022 Anexo A (controles técnicos) ----
const NIST_ISO: Record<string, string[]> = {
  'AC.2': ['A.8.2'], 'AC.3': ['A.5.15'], 'AC.6': ['A.8.2'], 'AC.7': ['A.8.5'],
  'AC.9': ['A.5.15'], 'AC.12': ['A.5.15'], 'AC.14': ['A.5.15'],
  'IA.4': ['A.5.17'], 'IA.5': ['A.5.17', 'A.8.5'], 'IA.10': ['A.8.5'],
  'AU.5': ['A.8.15'], 'AU.6': ['A.8.15', 'A.8.16'], 'AU.8': ['A.8.15'],
  'AU.9': ['A.8.15'], 'AU.12': ['A.8.15'], 'AU.14': ['A.8.15'],
  'CM.1': ['A.8.9'], 'CM.3': ['A.8.9', 'A.8.32'],
  'SC.5': ['A.8.20'], 'SC.7': ['A.8.20', 'A.8.22'], 'SC.8': ['A.8.24'],
  'SI.2': ['A.8.8'], 'SI.3': ['A.8.7'], 'SI.4': ['A.8.16'], 'SI.7': ['A.8.16'],
  'SA.11': ['A.8.29'],
};
const ISO_FALLBACK: Record<string, string[]> = {
  AC: ['A.5.15'], IA: ['A.8.5'], AU: ['A.8.15'], CM: ['A.8.9'], SC: ['A.8.20'], SI: ['A.8.16'], SA: ['A.8.25'],
};
const fam = (id: string): string => id.split(/[._]/)[0];
const nistToIso = (id: string): string[] => NIST_ISO[id] ?? ISO_FALLBACK[fam(id)] ?? [];

// ---- Ley 1581/Decreto 1074: query DIRECTA por control (evidencia real por tipo de
// evento, no crosswalk). Cada control se mapea a las señales que de verdad lo evidencian. ----
const LEY_QUERIES: { id: string; src: string; q: Record<string, unknown> }[] = [
  { id: 'L.SEG', src: 'señales: authentication, pam, sshd, sudo, adduser, access_control',
    q: { terms: { 'rule.groups': ['authentication_success', 'authentication_failed', 'authentication_failures', 'pam', 'sshd', 'sudo', 'adduser', 'access_control', 'win_authentication'] } } },
  { id: 'L.TRAZ', src: 'señales: config_changed, accesslog, web, nginx, syslog, audit',
    q: { terms: { 'rule.groups': ['config_changed', 'accesslog', 'web', 'nginx', 'syslog', 'audit'] } } },
  { id: 'L.DET', src: 'señales: ids, attack, malware, botnet, exfiltration, recon, web_scan',
    q: { terms: { 'rule.groups': ['ids', 'attack', 'attacks', 'malware', 'botnet', 'exfiltration', 'recon', 'web_scan'] } } },
  { id: 'L.INTEG', src: 'señales: syscheck (FIM), ossec',
    q: { terms: { 'rule.groups': ['syscheck', 'syscheck_file', 'syscheck_entry_modified', 'syscheck_entry_added', 'syscheck_entry_deleted', 'ossec'] } } },
  { id: 'L.VULN', src: 'señal: vulnerability-detector',
    q: { terms: { 'rule.groups': ['vulnerability-detector'] } } },
  { id: 'L.CIFR', src: 'señales: web_activity, dns, security_services',
    q: { terms: { 'rule.groups': ['web_activity', 'dns', 'security_services'] } } },
];
// Ruido benigno de alto volumen dentro de esos grupos (FIM checksum / audit systemd).
const LEY_NOISE = [{ terms: { 'rule.id': ['80792', '91578'] } }];

async function getLey1581(client: ReturnType<typeof getIndexerClient>, hours: number): Promise<FrameworkResult> {
  const aggs: Record<string, unknown> = {};
  for (const ctl of LEY_QUERIES) aggs[ctl.id] = { filter: ctl.q, aggs: { lvl: { max: { field: 'rule.level' } } } };
  aggs['_total'] = { filter: { bool: { should: LEY_QUERIES.map((c) => c.q), minimum_should_match: 1 } } };

  const res = await client.post(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
    size: 0,
    query: { bool: { filter: [{ range: { timestamp: { gte: `now-${hours}h`, lte: 'now' } } }], must_not: LEY_NOISE } },
    aggs,
  });
  const a = res.data.aggregations as Record<string, { doc_count?: number; lvl?: { value: number | null } }>;
  const controles: Control[] = LEY_QUERIES
    .map((ctl) => ({ id: ctl.id, count: a[ctl.id]?.doc_count ?? 0, level: Math.round(a[ctl.id]?.lvl?.value ?? 0), src: ctl.src }))
    .filter((c) => c.count > 0)
    .sort((x, y) => y.level - x.level || y.count - x.count);
  return { total: a['_total']?.doc_count ?? 0, controlesCubiertos: controles.length, controles, derivado: false };
}

/** Construye un marco derivado agregando controles fuente por el crosswalk dado. */
function deriveFrom(sources: { controles: Control[]; map: (id: string) => string[]; tag: string }[]): Control[] {
  const acc = new Map<string, { count: number; level: number; src: Set<string> }>();
  for (const s of sources) {
    for (const c of s.controles) {
      for (const t of s.map(c.id)) {
        const cur = acc.get(t) ?? { count: 0, level: 0, src: new Set<string>() };
        cur.count += c.count;
        cur.level = Math.max(cur.level, c.level);
        cur.src.add(`${s.tag}:${c.id}`);
        acc.set(t, cur);
      }
    }
  }
  return [...acc.entries()]
    .map(([id, v]) => ({ id, count: v.count, level: v.level, src: [...v.src].join(', ') }))
    .sort((a, b) => b.level - a.level || b.count - a.count);
}

const cache = new Map<number, { at: number; data: ComplianceData }>();
const TTL = 60_000;

export async function getCompliance(hours: number): Promise<ComplianceData> {
  const cached = cache.get(hours);
  if (cached && Date.now() - cached.at < TTL) return cached.data;

  const client = getIndexerClient();
  const aggs: Record<string, unknown> = {};
  for (const [key, field] of Object.entries(FIELDS)) {
    aggs[`${key}_total`] = { filter: { exists: { field } } };
    aggs[`${key}_cov`] = { cardinality: { field } };
    aggs[`${key}_ctrl`] = {
      terms: { field, size: 40, order: { _count: 'desc' } },
      aggs: { lvl: { max: { field: 'rule.level' } } },
    };
  }
  let data: { aggregations: Record<string, { doc_count?: number; value?: number; buckets?: { key: string; doc_count: number; lvl?: { value: number | null } }[] }> };
  try {
    const res = await client.post(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
      size: 0,
      query: { bool: { filter: [{ range: { timestamp: { gte: `now-${hours}h`, lte: 'now' } } }], must_not: COMPLIANCE_NOISE } },
      aggs,
    });
    data = res.data;
  } catch (err) {
    const e = err as { code?: string };
    if (e.code === 'ECONNREFUSED' || e.code === 'ETIMEDOUT') throw new HttpError(502, 'No se pudo conectar al Wazuh Indexer');
    throw new HttpError(502, 'Error consultando cumplimiento');
  }

  const frameworks: Record<string, FrameworkResult> = {};
  for (const key of Object.keys(FIELDS)) {
    const controles: Control[] = (data.aggregations[`${key}_ctrl`]?.buckets ?? []).map((b) => ({
      id: b.key, count: b.doc_count, level: Math.round(b.lvl?.value ?? 0),
    }));
    controles.sort((a, b) => b.level - a.level || b.count - a.count);
    frameworks[key] = {
      total: data.aggregations[`${key}_total`]?.doc_count ?? 0,
      controlesCubiertos: data.aggregations[`${key}_cov`]?.value ?? 0,
      controles,
    };
  }

  // ISO 27001: derivado por crosswalk desde NIST (Wazuh no lo etiqueta).
  const nistControles = frameworks.nist?.controles ?? [];
  const isoControles = deriveFrom([{ controles: nistControles, map: nistToIso, tag: 'NIST' }]);
  frameworks.iso27001 = { total: frameworks.nist?.total ?? 0, controlesCubiertos: isoControles.length, controles: isoControles, derivado: true };

  // Ley 1581: evidencia DIRECTA por control (query propia por tipo de evento).
  frameworks.ley1581 = await getLey1581(client, hours);

  const result: ComplianceData = { hours, frameworks };
  cache.set(hours, { at: Date.now(), data: result });
  return result;
}
