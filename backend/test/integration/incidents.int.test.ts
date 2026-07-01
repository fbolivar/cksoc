/** Integracion (BD real): ciclo de vida de incidentes + timeline. */
import { describe, it, expect, beforeAll } from 'vitest';
import { registerUser } from '../../src/modules/auth/auth.service';
import {
  createIncident, getIncident, updateIncident, addComment, listIncidents,
} from '../../src/modules/incidents/incidents.service';

let userId: string;

describe('incidentes (integracion con BD)', () => {
  beforeAll(async () => {
    const u = await registerUser(`inc-${Date.now()}@test.local`, 'password123', 'Analista Inc', 'analista');
    userId = u.id;
  });

  it('crear -> nota de sistema -> avanzar estado -> resolver (con closed_at)', async () => {
    const inc = await createIncident({ title: 'Incidente de prueba', severity: 'alta' }, userId);
    expect(inc.status).toBe('abierto');
    expect(inc.timeline).toHaveLength(1);
    expect(inc.timeline[0].kind).toBe('system');

    const enCurso = await updateIncident(inc.id, { status: 'en_curso' }, userId);
    expect(enCurso?.status).toBe('en_curso');
    expect(enCurso?.timeline.some((t) => t.kind === 'system' && t.note.includes('en_curso'))).toBe(true);

    await addComment(inc.id, 'Investigando el origen del evento', userId);

    const resuelto = await updateIncident(inc.id, { status: 'resuelto' }, userId);
    expect(resuelto?.status).toBe('resuelto');
    expect(resuelto?.closedAt).toBeTruthy();

    const full = await getIncident(inc.id);
    expect(full?.timeline.some((t) => t.kind === 'comment')).toBe(true);

    const list = await listIncidents({});
    expect(list.some((i) => i.id === inc.id)).toBe(true);
  });
});
