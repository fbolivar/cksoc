import { describe, it, expect } from 'vitest';
import { BAND_COLOR, BAND_LABEL } from './alerts';

describe('bandas de severidad de alertas', () => {
  it('cada banda con etiqueta tiene un color asociado', () => {
    for (const band of Object.keys(BAND_LABEL)) {
      expect(BAND_COLOR[band as keyof typeof BAND_COLOR]).toMatch(/^#|rgb|hsl/);
    }
  });

  it('define al menos 3 bandas', () => {
    expect(Object.keys(BAND_LABEL).length).toBeGreaterThanOrEqual(3);
  });
});
