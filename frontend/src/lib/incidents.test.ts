import { describe, it, expect } from 'vitest';
import { SEV, ST } from './incidents';

const SEVS = ['baja', 'media', 'alta', 'critica'] as const;
const STS = ['abierto', 'en_curso', 'resuelto', 'cerrado'] as const;

describe('mapas de incidentes', () => {
  it('SEV define color y etiqueta para cada severidad', () => {
    for (const k of SEVS) {
      expect(SEV[k].color).toMatch(/^#[0-9a-f]{3,8}$/i);
      expect(SEV[k].label.length).toBeGreaterThan(0);
    }
  });

  it('ST define color y etiqueta para cada estado', () => {
    for (const k of STS) {
      expect(ST[k].color).toMatch(/^#[0-9a-f]{3,8}$/i);
      expect(ST[k].label.length).toBeGreaterThan(0);
    }
  });
});
