/**
 * Agentico — analista SOC autónomo.
 *
 * Cada N minutos analiza la telemetría (eventos, alertas, incidentes, UEBA, mapa de
 * ataques, detección y respuesta), TOMA acciones seguras de contención y comunica el
 * resultado por Telegram con la voz de "Agentico", consultor especialista del SOC.
 *
 * PRINCIPIO RECTOR: no afectar la operación. La ÚNICA acción automática de contención es
 * el bloqueo TEMPORAL (auto-expira) de IPs EXTERNAS, públicas y CONFIRMADAS maliciosas
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

const CHAT_IDS = (env.TELEGRAM_CHAT_ID || '').split(',').map((s) => s.trim()).filter(Boolean);

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
const PERSONA = `Eres "Agentico", consultor especialista de un SOC gestionado (marca Click Solutions) asignado al cliente DG&A Abogados. Escribes un parte OPERATIVO breve para el equipo por Telegram.
Reglas:
- Español, tono profesional y tranquilo de analista senior. Sin markdown, sin asteriscos, sin comillas invertidas.
- Usa EXCLUSIVAMENTE los datos que se te entregan. NO inventes IPs, cifras ni hallazgos.
- 2 a 4 frases: lectura experta de la situación y por qué las acciones tomadas mantienen la postura sin afectar la operación.
- No repitas la lista de acciones (ya va aparte); aporta el CRITERIO, no el listado.`;

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
      await block({ ip, motivo, user: actor, expirySeconds: env.AGENTICO_BAN_SECONDS });
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

  // ---------- 3) COMUNICACIÓN ----------
  const ahora = new Date().toLocaleString('es-CO', { timeZone: 'America/Bogota', dateStyle: 'medium', timeStyle: 'short' });
  const lectura = await narrativa({
    ventanaHoras: lookback, amenazasExternas: threats.length,
    criticas30m, criticas6h, incidentesAbiertos: incAbiertos, incidentesCriticos: incCriticosAbiertos,
    anomaliasUeba: uebaOpen.length, ipsEnCuarentena: blockedList.length,
    bloqueosEjecutados: acciones.filter((a) => a.estado === 'bloqueada').length,
    topAtacantes: threats.slice(0, 5).map((o) => ({ pais: o.country, clasif: o.clasificacion, ip: o.ips[0] })),
  });

  const L: string[] = [];
  L.push('🛡️ Agentico · Consultor SOC — Click Solutions / DG&A');
  L.push(`⏱️ Turno automático · ventana ${lookback} h · ${ahora}${dryRun ? ' · (SIMULACIÓN)' : ''}`);
  if (lectura) { L.push(''); L.push(lectura); }
  L.push('');
  L.push('📊 Situación');
  L.push(`• Amenazas externas activas: ${threats.length}`);
  L.push(`• Alertas críticas: ${criticas30m} (30 min) / ${criticas6h} (${lookback} h)`);
  L.push(`• Eventos procesados (30 min): ${eventos30m.toLocaleString('es-CO')}`);
  L.push(`• Incidentes abiertos: ${incAbiertos} (críticos: ${incCriticosAbiertos})`);
  L.push(`• Anomalías UEBA abiertas: ${uebaOpen.length}`);
  L.push(`• IPs en cuarentena (firewall): ${blockedList.length}`);
  L.push('');
  const bloqueadas = acciones.filter((a) => a.estado === 'bloqueada');
  if (bloqueadas.length || acciones.length) {
    L.push('✅ Acciones ejecutadas');
    for (const a of acciones) {
      const icono = a.estado === 'bloqueada' ? '🚫 Contenida' : a.estado === 'rechazada' ? '⚠️ No bloqueada (regla de seguridad)' : '❌ Error';
      L.push(`• ${icono}: ${a.ip} (${a.pais}) — ${a.motivo}${a.detalle && a.estado !== 'bloqueada' ? ` [${a.detalle}]` : ''}`);
    }
    if (incidentesReconocidos) L.push(`• 📌 ${incidentesReconocidos} incidente(s) reconocido(s) tras contener al atacante`);
  } else {
    L.push('✅ Sin contención automática: no hay atacantes externos confirmados nuevos. La operación sigue normal.');
  }

  const recomendaciones: string[] = [];
  if (uebaOpen.length) recomendaciones.push(`Revisar ${uebaOpen.length} anomalía(s) de comportamiento (UEBA).`);
  if (incCriticosAbiertos) recomendaciones.push(`Atender ${incCriticosAbiertos} incidente(s) crítico(s) abierto(s).`);
  const sospechososSinBloquear = threats.filter((o) => o.clasificacion === 'sospechoso' && !blockedSet.has(o.ips[0]) && !o.ioc && o.abuseScore < env.AGENTICO_MIN_ABUSE).length;
  if (sospechososSinBloquear) recomendaciones.push(`${sospechososSinBloquear} origen(es) sospechoso(s) en observación (no cumplen umbral de bloqueo automático).`);
  if (recomendaciones.length) {
    L.push('');
    L.push('📝 Recomendaciones (para el analista)');
    recomendaciones.forEach((r) => L.push(`• ${r}`));
  }

  L.push('');
  L.push('— Agentico opera bajo el principio de NO afectar la operación: solo contiene atacantes externos confirmados de forma temporal (24 h, reversible); nunca IPs internas, del cliente ni legítimas.');
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
    yaBloqueadas: blockedList.length, acciones, incidentesReconocidos,
    autoblock: env.AGENTICO_AUTOBLOCK, telegram, mensaje,
  };
}
