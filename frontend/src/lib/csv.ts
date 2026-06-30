/**
 * Exportacion a CSV en el cliente (sin backend).
 * Genera un CSV con BOM UTF-8 (para que Excel respete los acentos) y dispara
 * la descarga. Cada celda se escapa segun RFC 4180.
 */
export interface CsvCol<T> {
  label: string;
  get: (row: T) => unknown;
}

function escapeCell(value: unknown): string {
  const s = value === null || value === undefined ? '' : String(value);
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function toCsv<T>(rows: T[], columns: CsvCol<T>[]): string {
  const header = columns.map((c) => escapeCell(c.label)).join(',');
  const body = rows.map((r) => columns.map((c) => escapeCell(c.get(r))).join(','));
  return ['﻿' + header, ...body].join('\r\n');
}

export function downloadCsv<T>(filename: string, rows: T[], columns: CsvCol<T>[]): void {
  const blob = new Blob([toCsv(rows, columns)], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/** Sello de fecha-hora para nombres de archivo: 2026-06-30_1432. */
export function fileStamp(): string {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}_${p(d.getHours())}${p(d.getMinutes())}`;
}
