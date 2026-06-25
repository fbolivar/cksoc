/**
 * Motor de evaluacion de reglas de notificacion.
 * Para cada regla habilitada: cuenta alertas que cumplen la condicion en la
 * ventana; si supera el umbral y paso el cooldown, dispara las notificaciones.
 */
import { listRules, markEvaluated, type AlertRule } from './rules.service';
import { countMatching } from '../wazuh/wazuh.service';
import { notifyForRule } from './notify.service';

/** True si la regla esta dentro de su periodo de cooldown (no debe re-disparar). */
function inCooldown(rule: AlertRule): boolean {
  if (!rule.lastTriggeredAt) return false;
  const elapsed = Date.now() - new Date(rule.lastTriggeredAt).getTime();
  return elapsed < rule.cooldownMinutes * 60_000;
}

/** Evalua todas las reglas habilitadas una vez. */
export async function evaluateRules(): Promise<void> {
  let rules: AlertRule[];
  try {
    rules = (await listRules()).filter((r) => r.enabled);
  } catch {
    return; // BD no disponible momentaneamente
  }

  for (const rule of rules) {
    if (inCooldown(rule)) continue;
    try {
      const count = await countMatching({
        windowMinutes: rule.windowMinutes,
        minLevel: rule.minLevel,
        ruleGroups: rule.ruleGroups,
      });
      const triggered = count >= rule.threshold;
      if (triggered) {
        await notifyForRule(rule, count);
      }
      await markEvaluated(rule.id, triggered);
    } catch (err) {
      // Un fallo en una regla (p.ej. Indexer caido) no debe frenar las demas.
      // eslint-disable-next-line no-console
      console.error(`Error evaluando regla "${rule.name}":`, err instanceof Error ? err.message : err);
    }
  }
}
