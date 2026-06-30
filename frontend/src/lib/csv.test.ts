import { describe, it, expect } from 'vitest';
import { toCsv } from './csv';

interface Row { a: string; b: number | null }

describe('toCsv', () => {
  it('genera BOM + encabezado + filas', () => {
    const csv = toCsv<Row>([{ a: 'x', b: 1 }], [
      { label: 'A', get: (r) => r.a },
      { label: 'B', get: (r) => r.b },
    ]);
    expect(csv.startsWith('﻿')).toBe(true);
    expect(csv).toContain('A,B');
    expect(csv).toContain('x,1');
  });

  it('escapa comas, comillas y saltos de línea (RFC 4180)', () => {
    const csv = toCsv<{ v: string }>([{ v: 'a,b "c"\nd' }], [{ label: 'V', get: (r) => r.v }]);
    expect(csv).toContain('"a,b ""c""\nd"');
  });

  it('representa null/undefined como celda vacía', () => {
    const csv = toCsv<Row>([{ a: '', b: null }], [
      { label: 'A', get: (r) => r.a },
      { label: 'B', get: (r) => r.b },
    ]);
    expect(csv.split('\r\n')[1]).toBe(',');
  });
});
