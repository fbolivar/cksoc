/**
 * Dashboard de Office 365: agrega los eventos de la Management Activity API que
 * Wazuh ingesta (data.office365.*) para dar visibilidad tipo "módulo O365" de
 * Wazuh: top usuarios, IPs cliente (con país), operaciones, workloads, reglas,
 * sign-ins de Azure AD (éxito/fallo, origen, dispositivo) y actividad de
 * archivos (OneDrive/SharePoint — señal de exfiltración).
 */
import { getIndexerClient } from '../wazuh/wazuh.client';
import { env } from '../../config/env';
import { geolocate, isPublicIP } from '../geo/geoip.service';

const RANGE: Record<string, string> = { '24h': 'now-24h', '7d': 'now-7d', '30d': 'now-30d' };
const O365_FILTER = { bool: { should: [{ match: { 'rule.groups': 'office365' } }, { exists: { field: 'data.office365' } }], minimum_should_match: 1 } };

export interface NamedCount { key: string; count: number; country?: string }
export interface RuleCount { desc: string; count: number; level: number }
export interface TimePoint { ts: number; count: number }

export interface O365Overview {
  range: string;
  total: number;
  users: number;
  clientIps: number;
  signIns: number;
  signInsFailed: number;
  downloads: number;
  timeline: TimePoint[];
  topUsers: NamedCount[];
  topClientIps: NamedCount[];
  topOperations: NamedCount[];
  workloads: NamedCount[];
  topRules: RuleCount[];
  signInUsers: NamedCount[];
  signInIps: NamedCount[];
  fileTopUsers: NamedCount[];
  generatedAt: string;
}

interface TermB { key: string; doc_count: number }
interface RuleB extends TermB { lvl: { value: number | null } }

function withGeo(buckets: TermB[]): NamedCount[] {
  return buckets.map((b) => {
    const g = isPublicIP(b.key) ? geolocate(b.key) : null;
    return { key: b.key, count: b.doc_count, country: g?.country || (isPublicIP(b.key) ? '' : 'interna') };
  });
}

async function search(body: object): Promise<{ hits: { total: { value: number } | number }; aggregations?: Record<string, { buckets?: TermB[]; value?: number }> }> {
  const { data } = await getIndexerClient().post(`/${env.WAZUH_ALERTS_INDEX}/_search`, body);
  return data as { hits: { total: { value: number } | number }; aggregations?: Record<string, { buckets?: TermB[]; value?: number }> };
}

const RANGE_INTERVAL: Record<string, string> = { '24h': '1h', '7d': '1d', '30d': '1d' };

export async function getO365Overview(rangeIn: string): Promise<O365Overview> {
  const range = RANGE[rangeIn] ? rangeIn : '24h';
  const gte = RANGE[range];
  const base = [{ range: { '@timestamp': { gte } } }, O365_FILTER];

  // 1) Agregación principal
  const main = await getIndexerClient().post<{
    hits: { total: { value: number } | number };
    aggregations: {
      users: { buckets: TermB[] }; ips: { buckets: TermB[] }; ops: { buckets: TermB[] };
      workloads: { buckets: TermB[] }; rules: { buckets: RuleB[] };
      timeline: { buckets: { key: number; doc_count: number }[] };
      cUsers: { value: number }; cIps: { value: number };
      signin: { doc_count: number }; signinFail: { doc_count: number }; downloads: { doc_count: number };
    };
  }>(`/${env.WAZUH_ALERTS_INDEX}/_search`, {
    size: 0,
    query: { bool: { filter: base } },
    aggs: {
      users: { terms: { field: 'data.office365.UserId', size: 15 } },
      ips: { terms: { field: 'data.office365.ClientIP', size: 15 } },
      ops: { terms: { field: 'data.office365.Operation', size: 15 } },
      workloads: { terms: { field: 'data.office365.Workload', size: 12 } },
      rules: { terms: { field: 'rule.description', size: 12 }, aggs: { lvl: { max: { field: 'rule.level' } } } },
      timeline: { date_histogram: { field: '@timestamp', fixed_interval: RANGE_INTERVAL[range], min_doc_count: 0, extended_bounds: { min: gte, max: 'now' } } },
      cUsers: { cardinality: { field: 'data.office365.UserId' } },
      cIps: { cardinality: { field: 'data.office365.ClientIP' } },
      signin: { filter: { term: { 'data.office365.Operation': 'UserLoggedIn' } } },
      signinFail: { filter: { term: { 'data.office365.Operation': 'UserLoginFailed' } } },
      downloads: { filter: { term: { 'data.office365.Operation': 'FileDownloaded' } } },
    },
  });
  const a = main.data.aggregations;
  const total = typeof main.data.hits.total === 'number' ? main.data.hits.total : main.data.hits.total.value;

  // 2) Sign-ins: origen (ActorIpAddress) y usuarios
  const si = await search({
    size: 0,
    query: { bool: { filter: [...base, { terms: { 'data.office365.Operation': ['UserLoggedIn', 'UserLoginFailed'] } }] } },
    aggs: {
      ipsrc: { terms: { field: 'data.office365.ActorIpAddress', size: 10 } },
      suser: { terms: { field: 'data.office365.UserId', size: 10 } },
    },
  });

  // 3) Actividad de archivos: top usuarios que descargan/modifican (señal de exfil)
  const fa = await search({
    size: 0,
    query: { bool: { filter: [...base, { terms: { 'data.office365.Operation': ['FileDownloaded', 'FileModified', 'FileModifiedExtended', 'FileUploaded', 'FileSyncDownloadedFull'] } }] } },
    aggs: { dusers: { terms: { field: 'data.office365.UserId', size: 10 } } },
  });

  return {
    range,
    total,
    users: a.cUsers.value,
    clientIps: a.cIps.value,
    signIns: a.signin.doc_count,
    signInsFailed: a.signinFail.doc_count,
    downloads: a.downloads.doc_count,
    timeline: a.timeline.buckets.map((b) => ({ ts: b.key, count: b.doc_count })),
    topUsers: a.users.buckets.map((b) => ({ key: b.key, count: b.doc_count })),
    topClientIps: withGeo(a.ips.buckets),
    topOperations: a.ops.buckets.map((b) => ({ key: b.key, count: b.doc_count })),
    workloads: a.workloads.buckets.map((b) => ({ key: b.key, count: b.doc_count })),
    topRules: a.rules.buckets.map((b) => ({ desc: b.key, count: b.doc_count, level: Math.round(b.lvl.value ?? 0) })),
    signInUsers: (si.aggregations?.suser?.buckets ?? []).map((b) => ({ key: b.key, count: b.doc_count })),
    signInIps: withGeo(si.aggregations?.ipsrc?.buckets ?? []),
    fileTopUsers: (fa.aggregations?.dusers?.buckets ?? []).map((b) => ({ key: b.key, count: b.doc_count })),
    generatedAt: new Date().toISOString(),
  };
}
