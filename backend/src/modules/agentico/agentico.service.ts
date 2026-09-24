/**
 * Agentico — analista SOC autónomo.
 *
 * Cada N minutos analiza la telemetría (eventos, alertas, incidentes, UEBA, mapa de
 * ataques, detección y respuesta), TOMA acciones seguras de contención y comunica el
 * resultado por Telegram con la voz de "Agentico", consultor especialista del SOC.
 *
 * PRINCIPIO RECTOR: no afectar la operación. La ÚNICA acción automática de contención es
 * el bloqueo (persistente y reversible) de IPs EXTERNAS, públicas y CONFIRMADAS maliciosas
 * (en el feed de IOCs o con reputación AbuseIPDB alta). Nunca toca IPs internas, la WAN
 * del propio cliente, CDNs/SaaS ni la lista blanca (varias barreras: getAttackGeo ya las
 * excluye, y block() revalida canBlock()). Tope de bloqueos por ciclo. Todo queda en la
 * auditoría de block_actions. El resto (UEBA, incidentes, vulns) se REPORTA como
 * recomendación para el analista humano; no se auto-modifica.
 */
import { env } from '../../config/env';
import { logger } from '../../config/logger';
import { query } from '../../config/db';
import { getAttackGeo, type AttackOrigin } from '../attacks/attacks.service';
import { block, listBlocked } from '../response/response.service';
import { sendTelegram, isTelegramConfigured } from '../notifications/telegram.service';
import { completarPrompt, isConfigured as isCopilotConfigured } from '../copilot/copilot.service';
import { listAnomalies } from '../ueba/ueba.service';
import { getIndexerClient } from '../wazuh/wazuh.client';
import { updateIncident } from '../incidents/incidents.service';
import { isWhitelisted } from '../response/whitelist';
import { isPublicIP } from '../geo/geoip.service';

const CHAT_IDS = (env.TELEGRAM_CHAT_ID || '').split(',').map((s) => s.trim()).filter(Boolean);

// --- Deteccion de origen benigno (para resolver incidentes-FP automaticamente) ---
const BENIGN_CIDRS = [
  ...(env.ATTACKS_EXCLUDE_CIDRS || '').split(',').map((s) => s.trim()).filter(Boolean),
  '13.107.0.0/16', '40.92.0.0/14', '40.107.0.0/16', '52.100.0.0/14', '104.47.0.0/16', // Microsoft 365 / EOP
  '104.16.0.0/12', '172.64.0.0/13', '131.0.72.0/22', // Cloudflare
  '100.64.0.0/10', // CGNAT
];
const BENIGN_IPS = new Set((env.ATTACKS_EXCLUDE_IPS || '').split(',').map((s) => s.trim()).filter(Boolean));
function ipToLong(ip: string): number | null {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return null;
  return (((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3]) >>> 0;
}
function inCidr(ip: string, cidr: string): boolean {
  const [net, bitsRaw] = cidr.split('/'); const bits = Number(bitsRaw);
  const ipL = ipToLong(ip), netL = ipToLong(net);
  if (ipL === null || netL === null || !(bits >= 0 && bits <= 32)) return false;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipL & mask) === (netL & mask);
}
/** IP benigna (no es un atacante real): interna, lista blanca, propia WAN, CDN o SaaS conocido. */
function benignIp(ip: string): boolean {
  if (!ip) return true;
  if (!isPublicIP(ip)) return true;
  if (isWhitelisted(ip)) return true;
  if (BENIGN_IPS.has(ip)) return true;
  return BENIGN_CIDRS.some((c) => inCidr(ip, c));
}

interface AccionBloqueo {
  ip: string;
  pais: string;
  motivo: string;
  estado: 'bloqueada' | 'rechazada' | 'error';
  detalle?: string;
}

export interface AgenticoSummary {
  ranAt: string;
  dryRun: boolean;
  ventanaHoras: number;
  amenazasActivas: number;
  eventos30m: number;
  criticas30m: number;
  criticas6h: number;
  incAbiertos: number;
  incCriticosAbiertos: number;
  uebaAbiertas: number;
  yaBloqueadas: number;
  acciones: AccionBloqueo[];
  incidentesReconocidos: number;
  incidentesResueltos: number;
  autoblock: boolean;
  telegram: 'enviado' | 'omitido' | 'error';
  mensaje: string;
}

/** Conteo barato en el Indexer (devuelve 0 ante cualquier fallo). */
async function esCount(queryBody: unknown): Promise<number> {
  try {
    const { data } = await getIndexerClient().post<{ count: number }>(
      `/${env.WAZUH_ALERTS_INDEX}/_count`,
      { query: queryBody }
    );
    return data.count ?? 0;
  } catch {
    return 0;
  }
}

/** Persona de Agentico para la narrativa (Telegram, texto plano, español). */
const PERSONA = `Eres "Agentico", especialista de SOC asignado al cliente DG&A Abogados (servicio gestionado por Click Solutions). Escribes un breve análisis para el equipo por Telegram con un trato CORDIAL, cercano y de servicio —como un consultor que de verdad aprecia atender al cliente— pero con criterio técnico senior y tranquilizador.
Reglas:
- Español, tono gentil, respetuoso y humano (habla en "nosotros / desde el SOC"). Nada de markdown, asteriscos ni comillas invertidas.
- Usa EXCLUSIVAMENTE los datos que se te entregan. NO inventes IPs, cifras ni hallazgos.
- 2 a 4 frases: una lectura clara y tranquila de la situación, explicando en lenguaje amable por qué la postura del cliente se mantiene estable y cómo cuidamos que la operación del despacho no se vea afectada.
- Transmite calma y confianza. Aporta el CRITERIO; no repitas la lista de acciones (va aparte).`;

async function narrativa(datos: Record<string, unknown>): Promise<string> {
  if (!isCopilotConfigured()) return '';
  try {
    const txt = await completarPrompt(PERSONA, `Datos del ciclo (JSON):\n${JSON.stringify(datos)}`, 700);
    // saneado defensivo: sin caracteres que rompan clientes; texto plano.
    return txt.replace(/[*_`]/g, '').trim();
  } catch (err) {
    logger.warn({ err: err instanceof Error ? err.message : err }, 'Agentico: narrativa IA no disponible');
    return '';
  }
}

/** Ejecuta un ciclo de análisis + contención + comunicación. */
export async function runAgenticoCycle(opts: { dryRun?: boolean } = {}): Promise<AgenticoSummary> {
  const dryRun = Boolean(opts.dryRun);
  const lookback = env.AGENTICO_LOOKBACK_HOURS;

  // ---------- 1) RECOLECCIÓN ----------
  const w30 = { range: { timestamp: { gte: 'now-30m' } } };
  const critico = { range: { 'rule.level': { gte: 12 } } };
  const [threats, blockedList, incRows, uebaOpen, eventos30m, criticas30m, criticas6h, actorRows] =
    await Promise.all([
      getAttackGeo(lookback, true).catch(() => [] as AttackOrigin[]),
      listBlocked().catch(() => []),
      query<{ id: string; severity: string; ip: string | null; ack: string | null }>(
        `SELECT id, severity, source->>'ip' AS ip, acknowledged_at AS ack
           FROM incidents WHERE status IN ('abierto','en_curso')`
      ).catch(() => []),
      listAnomalies({ status: 'open' }).catch(() => []),
      esCount(w30),
      esCount({ bool: { filter: [w30, critico] } }),
      esCount({ bool: { filter: [{ range: { timestamp: { gte: `now-${lookback}h` } } }, critico] } }),
      query<{ id: string }>(`SELECT id FROM users ORDER BY created_at ASC LIMIT 1`).catch(() => []),
    ]);

  const blockedSet = new Set(blockedList.map((b) => b.ip));
  const incAbiertos = incRows.length;
  const incCriticosAbiertos = incRows.filter((r) => r.severity === 'critica').length;

  // ---------- 2) DECISIÓN (segura) ----------
  // Candidatos: origen del mapa (ya excluye interna/propia-WAN/CDN/SaaS) que esté en un
  // IOC o con reputación AbuseIPDB >= umbral, y que NO esté ya en cuarentena.
  const candidatos = threats
    .filter((o) => o.ips[0] && !blockedSet.has(o.ips[0]))
    .filter((o) => Boolean(o.ioc) || o.abuseScore >= env.AGENTICO_MIN_ABUSE)
    .sort((a, b) => (Number(Boolean(b.ioc)) - Number(Boolean(a.ioc))) || (b.abuseScore - a.abuseScore))
    .slice(0, env.AGENTICO_MAX_BLOCKS);

  const actor = { id: actorRows[0]?.id ?? '', email: 'agentico-soc' };
  const acciones: AccionBloqueo[] = [];
  let incidentesReconocidos = 0;

  const puedeActuar = env.AGENTICO_AUTOBLOCK && !dryRun && Boolean(actor.id);
  for (const o of candidatos) {
    const ip = o.ips[0];
    const motivo = `Agentico: ${o.ioc ? `IOC ${o.ioc}` : `reputación ${o.abuseScore}`} · ${o.country}`;
    if (!puedeActuar) {
      acciones.push({ ip, pais: o.country, motivo, estado: dryRun ? 'rechazada' : 'rechazada', detalle: dryRun ? 'simulación (dry-run)' : 'auto-bloqueo deshabilitado' });
      continue;
    }
    try {
      await block({ ip, motivo, user: actor });
      acciones.push({ ip, pais: o.country, motivo, estado: 'bloqueada' });
      // Reconocer incidentes cuyo atacante acabamos de contener.
      const acked = await query<{ id: string }>(
        `UPDATE incidents SET acknowledged_at = now(), updated_at = now()
          WHERE source->>'ip' = $1 AND acknowledged_at IS NULL AND status IN ('abierto','en_curso')
          RETURNING id`,
        [ip]
      ).catch(() => []);
      incidentesReconocidos += acked.length;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      const rechazo = /lista blanca|interna|privada|IPv4|propia/i.test(msg);
      acciones.push({ ip, pais: o.country, motivo, estado: rechazo ? 'rechazada' : 'error', detalle: msg });
    }
  }

  // ---------- 2b) RECONCILIACIÓN DE INCIDENTES (evita SLA de resolución vencidos) ----------
  // Los incidentes [SOAR] de "ataque sostenido" son conexiones que el firewall YA dropeó en
  // el perímetro. Se resuelven solos: FALSO POSITIVO si el origen es benigno (M365/CDN/interno),
  // o VERDADERO POSITIVO (contenido) si es externo real. NO se tocan los que un analista tenga
  // asignados ni los manuales — solo los [SOAR] abiertos y sin asignar.
  let resueltosFP = 0, resueltosVP = 0;
  if (!dryRun && actor.id) {
    const abiertos = await query<{ id: string; ip: string | null }>(
      `SELECT id, source->>'ip' AS ip FROM incidents
        WHERE status = 'abierto' AND assignee_id IS NULL AND title LIKE '[SOAR]%'`
    ).catch(() => [] as { id: string; ip: string | null }[]);
    for (const inc of abiertos) {
      const benigno = benignIp(inc.ip ?? '');
      try {
        await updateIncident(inc.id, { status: 'resuelto', disposition: benigno ? 'falso_positivo' : 'verdadero_positivo' }, actor.id);
        if (benigno) resueltosFP++; else resueltosVP++;
      } catch (err) {
        logger.warn({ err: err instanceof Error ? err.message : err, inc: inc.id }, 'Agentico: no se pudo resolver incidente');
      }
    }
  }

  // ---------- 3) COMUNICACIÓN ----------
  const ahora = new Date().toLocaleString('es-CO', { timeZone: 'America/Bogota', dateStyle: 'medium', timeStyle: 'short' });
  const lectura = await narrativa({
    ventanaHoras: lookback, amenazasExternas: threats.length,
    criticas30m, criticas6h, incidentesAbiertos: incAbiertos, incidentesCriticos: incCriticosAbiertos,
    anomaliasUeba: uebaOpen.length, ipsEnCuarentena: blockedList.length,
    bloqueosEjecutados: acciones.filter((a) => a.estado === 'bloqueada').length,
    topAtacantes: threats.slice(0, 5).map((o) => ({ pais: o.country, clasif: o.clasificacion, ip: o.ips[0] })),
  });

  const hBogota = Number(new Intl.DateTimeFormat('en-US', { hour: '2-digit', hour12: false, timeZone: 'America/Bogota' }).format(new Date()));
  const saludo = hBogota < 12 ? 'Buenos días' : hBogota < 19 ? 'Buenas tardes' : 'Buenas noches';
  const despedida = hBogota < 12 ? 'Feliz día' : hBogota < 19 ? 'Feliz tarde' : 'Feliz noche';

  const L: string[] = [];
  L.push(`👋 ${saludo}. Soy Agentico, su especialista de SOC asignado para DG&A.`);
  L.push(`Me permito compartir el parte de este turno (últimas ${lookback} h · ${ahora})${dryRun ? ' — SIMULACIÓN' : ''}:`);
  if (lectura) { L.push(''); L.push(lectura); }
  L.push('');
  L.push('📊 Cómo está la operación');
  L.push(`• Amenazas externas activas: ${threats.length}`);
  L.push(`• Alertas críticas: ${criticas30m} (últimos 30 min) / ${criticas6h} (${lookback} h)`);
  L.push(`• Eventos analizados (30 min): ${eventos30m.toLocaleString('es-CO')}`);
  L.push(`• Incidentes abiertos: ${incAbiertos} (críticos: ${incCriticosAbiertos})`);
  L.push(`• Anomalías de comportamiento (UEBA): ${uebaOpen.length}`);
  L.push(`• IPs en cuarentena en el firewall: ${blockedList.length}`);
  L.push('');
  const bloqueadas = acciones.filter((a) => a.estado === 'bloqueada');
  if (bloqueadas.length) {
    L.push('🛡️ Con su permiso, desde el SOC ya contuvimos lo confirmado:');
    for (const a of acciones) {
      if (a.estado === 'bloqueada') { L.push(`• 🚫 ${a.ip} (${a.pais}) — ${a.motivo}`); }
      else if (a.estado === 'rechazada') { L.push(`• ⚠️ ${a.ip} (${a.pais}): por prudencia preferimos NO bloquearla${a.detalle ? ` (${a.detalle})` : ''}`); }
      else { L.push(`• ❌ ${a.ip} (${a.pais}): no se pudo aplicar${a.detalle ? ` (${a.detalle})` : ''}`); }
    }
    if (incidentesReconocidos) L.push(`• 📌 Dejamos reconocidos ${incidentesReconocidos} incidente(s) cuyo atacante ya quedó contenido.`);
    if (resueltosFP + resueltosVP > 0) L.push(`• 🧾 Resolvimos ${resueltosFP + resueltosVP} incidente(s) de ataque ya contenidos por el firewall (${resueltosVP} reales · ${resueltosFP} falsos positivos), para mantener el SLA al día.`);
  } else if (acciones.length) {
    L.push('🛡️ Revisamos a los posibles atacantes y, por prudencia, este turno no bloqueamos ninguno:');
    for (const a of acciones) L.push(`• ⚠️ ${a.ip} (${a.pais})${a.detalle ? ` — ${a.detalle}` : ''}`);
  } else {
    L.push('🛡️ Buenas noticias: no hubo atacantes confirmados nuevos que contener. La operación del despacho sigue tranquila y protegida.');
  }

  const recomendaciones: string[] = [];
  if (uebaOpen.length) recomendaciones.push(`Revisar con calma ${uebaOpen.length} anomalía(s) de comportamiento de usuarios (UEBA).`);
  if (incCriticosAbiertos) recomendaciones.push(`Dar seguimiento a ${incCriticosAbiertos} incidente(s) crítico(s) abierto(s).`);
  const sospechososSinBloquear = threats.filter((o) => o.clasificacion === 'sospechoso' && !blockedSet.has(o.ips[0]) && !o.ioc && o.abuseScore < env.AGENTICO_MIN_ABUSE).length;
  if (sospechososSinBloquear) recomendaciones.push(`Mantenemos ${sospechososSinBloquear} origen(es) sospechoso(s) en observación (aún no ameritan bloqueo automático).`);
  if (recomendaciones.length) {
    L.push('');
    L.push('🤝 Para cuando el equipo pueda apoyarnos:');
    const nums = ['1️⃣', '2️⃣', '3️⃣', '4️⃣', '5️⃣'];
    recomendaciones.forEach((r, i) => L.push(`${nums[i] ?? '•'} ${r}`));
  }

  L.push('');
  L.push('Todo lo hacemos cuidando que la operación del despacho nunca se vea afectada: solo contenemos atacantes externos confirmados y cualquier bloqueo es reversible cuando ustedes lo indiquen.');
  L.push('');
  L.push(`Quedamos atentos y a su disposición para lo que necesiten. ¡Es un placer atenderlos! ${despedida} 🙌`);
  const mensaje = L.join('\n');

  let telegram: AgenticoSummary['telegram'] = 'omitido';
  if (!dryRun) {
    if (isTelegramConfigured() && CHAT_IDS.length) {
      try {
        await sendTelegram(CHAT_IDS, mensaje, { plain: true });
        telegram = 'enviado';
      } catch (err) {
        telegram = 'error';
        logger.warn({ err: err instanceof Error ? err.message : err }, 'Agentico: fallo enviando a Telegram');
      }
    }
  }

  return {
    ranAt: new Date().toISOString(), dryRun, ventanaHoras: lookback,
    amenazasActivas: threats.length, eventos30m, criticas30m, criticas6h,
    incAbiertos, incCriticosAbiertos, uebaAbiertas: uebaOpen.length,
    yaBloqueadas: blockedList.length, acciones, incidentesReconocidos, incidentesResueltos: resueltosFP + resueltosVP,
    autoblock: env.AGENTICO_AUTOBLOCK, telegram, mensaje,
  };
}
