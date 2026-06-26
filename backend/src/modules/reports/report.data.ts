/**
 * Recoleccion de datos para un reporte (un rango de tiempo).
 * Reutiliza los servicios de Wazuh (Indexer + API).
 */
import {
  getSummary,
  getTimeline,
  getTopAgents,
  getMitre,
  type AlertsSummary,
} from '../wazuh/wazuh.service';
import { getAgentsSummary, type AgentsSummary } from '../wazuh/agents.service';
import { getVulnerabilities, type VulnData } from '../vulnerabilities/vuln.service';
import { getSca, type ScaData } from '../sca/sca.service';
import { getFim, type FimData } from '../fim/fim.service';

export interface ReportData {
  range: string;
  generatedAt: string;
  summary: AlertsSummary;
  timeline: { ts: string; count: number }[];
  topAgents: { agent: string; count: number }[];
  mitre: { technique: string; count: number }[];
  agents: AgentsSummary | null;
  // Postura de endpoints (capacidades nuevas)
  vuln: VulnData | null;
  sca: ScaData | null;
  fim: FimData | null;
}

function intervalFor(range: string): string {
  if (range.endsWith('h')) return '1h';
  if (range === '7d') return '3h';
  return '1d';
}

function hoursFor(range: string): number {
  if (range === '7d') return 168;
  if (range === '30d') return 720;
  return 24;
}

export async function collectReportData(range: string): Promise<ReportData> {
  const [summary, timeline, topAgents, mitre, agents, vuln, sca, fim] = await Promise.all([
    getSummary(range),
    getTimeline(range, intervalFor(range)),
    getTopAgents(range, 8),
    getMitre(range, 8),
    getAgentsSummary().catch(() => null),
    getVulnerabilities().catch(() => null),
    getSca().catch(() => null),
    getFim(hoursFor(range)).catch(() => null),
  ]);
  return {
    range,
    generatedAt: new Date().toISOString(),
    summary,
    timeline,
    topAgents,
    mitre,
    agents,
    vuln,
    sca,
    fim,
  };
}
