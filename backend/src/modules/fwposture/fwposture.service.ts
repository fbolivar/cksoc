/**
 * Reporte de postura de seguridad del SonicWall: recolecta (solo lectura) el
 * Security Rating nativo + la config, corre checks deterministas de mejores
 * prácticas, y usa la IA (Claude) para redactar/priorizar el informe. La IA NO
 * inventa hallazgos: solo trabaja sobre los datos y checks entregados.
 */
import { collectFwSnapshot, type FwSnapshot } from './fwposture.collect';
import { runChecks, resumenChecks, type Check } from './fwposture.checks';
import { completarPrompt, isConfigured as isCopilotConfigured } from '../copilot/copilot.service';
import { buildFwPostureHtml } from './fwposture.template';
import { logger } from '../../config/logger';

export interface FwPosture {
  generatedAt: string;
  device: FwSnapshot['device'];
  checks: Check[];
  resumen: ReturnType<typeof resumenChecks>;
  iaDisponible: boolean;
  ia: string;               // narrativa del analista IA (markdown)
  snapshot: FwSnapshot;
}

const SYSTEM = `Eres un auditor senior de seguridad de firewalls SonicWall. Redactas un informe de POSTURA de seguridad del equipo para un SOC en Colombia.

Reglas estrictas:
- Usa EXCLUSIVAMENTE los datos que se te entregan (checks, Security Rating de SonicWall y configuración). NO inventes hallazgos, valores ni funciones.
- Español, tono de consultor senior, claro y accionable.
- Cuando cites un problema, explica el RIESGO de negocio y da la REMEDIACIÓN concreta (comando CLI si aplica).
- No repitas literalmente la tabla de checks; interprétala y prioriza.

Estructura EXACTA de tu respuesta (usa **negritas** para los títulos):
**Veredicto general**: 2-3 frases con el estado de seguridad del equipo.
**Hallazgos prioritarios**: lista, primero los de mayor severidad/incumplidos, cada uno con riesgo + remediación.
**Fortalezas**: qué está bien configurado.
**Top 3 acciones**: las 3 medidas de mayor impacto, en orden.`;

async function analizarIA(snapshot: FwSnapshot, checks: Check[], resumen: ReturnType<typeof resumenChecks>): Promise<string> {
  const srRaw = snapshot.securityRating ? JSON.stringify(snapshot.securityRating) : 'no disponible';
  const contexto = {
    equipo: snapshot.device,
    puntajeChecks: resumen,
    checks: checks.map((c) => ({ control: c.titulo, severidad: c.severidad, estado: c.estado, evidencia: c.evidencia })),
    ajustesGlobales: snapshot.global,
    administradores: snapshot.admins.map((a) => ({ nombre: a.name, perfil: a.profile, doble_factor: a.twoFactor, origen_abierto: a.trusthostOpen })),
    politicas: { total: snapshot.policies.total, any_any_accept: snapshot.policies.anyAnyAccept, sin_utm: snapshot.policies.sinUtmAccept, sin_log: snapshot.policies.sinLog },
    interfaces: snapshot.interfaces.map((i) => ({ nombre: i.name, wan: i.wan, gestion: i.allowaccess })),
    snmp_v1v2c: snapshot.snmpCommunities,
    security_rating_fortinet: srRaw.slice(0, 3500),
  };
  const user = `Datos de postura del SonicWall (JSON):\n${JSON.stringify(contexto)}`;
  return completarPrompt(SYSTEM, user, 2600);
}

export async function generateFwPosture(): Promise<FwPosture> {
  const snapshot = await collectFwSnapshot();
  const checks = runChecks(snapshot);
  const resumen = resumenChecks(checks);
  const iaDisponible = isCopilotConfigured();
  let ia = '';
  if (iaDisponible) {
    ia = await analizarIA(snapshot, checks, resumen).catch((err) => {
      logger.warn({ err: err instanceof Error ? err.message : err }, 'fwposture: análisis IA falló');
      return '';
    });
  }
  return { generatedAt: new Date().toISOString(), device: snapshot.device, checks, resumen, iaDisponible, ia, snapshot };
}

/** HTML del reporte (para vista previa / PDF). */
export async function generateFwPostureHtml(): Promise<{ posture: FwPosture; html: string }> {
  const posture = await generateFwPosture();
  return { posture, html: buildFwPostureHtml(posture) };
}
