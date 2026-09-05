/** Tipos y llamadas a la API de reportes. */
import { api } from './api';

export interface Report {
  id: string;
  title: string;
  type: 'manual' | 'scheduled';
  format: string;
  params: { preset?: string; desde?: string; hasta?: string; label?: string; range?: string };
  status: string;
  created_at: string;
}

// ----------------- Informe gerencial (Dirección / Comité) -----------------

export interface PresetPeriodo {
  value: string;
  label: string;
}

export interface ExecReportRef {
  id: string;
  mes: string;
  desde: string | null;
  hasta: string | null;
  periodoLabel: string | null;
  estado: 'borrador' | 'revisado' | 'enviado';
  generado_en?: string;
  enviado_en?: string | null;
}

/** Texto de cada sección del informe (el editado, o el generado automáticamente). */
export interface TextosInforme {
  resumen: string;
  introduccion: string;
  objetivos: string;
  alcance: string;
  resultados: string;
  analisis: string;
  conclusiones: string;
  recomendaciones: string;
  planAccion: string;
  hojaRuta: string;
  novedades: string;
}

export type ClaveSeccion = keyof TextosInforme;

export interface ExecPreview {
  report: ExecReportRef;
  html: string;
  textos: TextosInforme;
  /** Secciones que tienen texto editado manualmente (no el automático). */
  editadas: ClaveSeccion[];
}

export interface PeriodoInput {
  preset?: string;
  desde?: string;
  hasta?: string;
}

/** Nombre de archivo sugerido para la descarga. */
function nombrePdf(r: ExecReportRef): string {
  const p = r.desde && r.hasta ? `${r.desde}_a_${r.hasta}` : r.mes;
  return `Informe-Gerencial-Seguridad-${p}.pdf`;
}

export const executiveApi = {
  presets: () =>
    api.get<{ presets: PresetPeriodo[] }>('/reports/executive/presets').then((r) => r.data.presets),

  generate: (periodo: PeriodoInput) =>
    api.post<ExecPreview>('/reports/executive/generate', periodo).then((r) => r.data),

  get: (id: string) => api.get<ExecPreview>(`/reports/executive/${id}`).then((r) => r.data),

  update: (id: string, textos: Partial<TextosInforme>) =>
    api.put<ExecPreview>(`/reports/executive/${id}`, textos).then((r) => r.data),

  approve: (id: string) =>
    api.post<{ report: ExecReportRef }>(`/reports/executive/${id}/approve`).then((r) => r.data.report),

  send: (id: string) =>
    api.post<{ recipients: string[] }>(`/reports/executive/${id}/send`).then((r) => r.data),

  remove: (id: string) => api.delete(`/reports/executive/${id}`).then((r) => r.data),

  history: () =>
    api.get<{ reports: ExecReportRef[] }>('/reports/executive/history').then((r) => r.data.reports),

  download: async (r: ExecReportRef) => {
    const res = await api.get(`/reports/executive/${r.id}/download`, { responseType: 'blob' });
    const url = URL.createObjectURL(res.data as Blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = nombrePdf(r);
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },
};

export const reportsApi = {
  list: () => api.get<{ reports: Report[] }>('/reports').then((r) => r.data.reports),

  presets: () =>
    api.get<{ presets: PresetPeriodo[] }>('/reports/presets').then((r) => r.data.presets),

  generate: (input: { title: string } & PeriodoInput) =>
    api.post<{ report: Report }>('/reports/generate', input).then((r) => r.data.report),

  /** HTML del informe archivado, para previsualizarlo sin descargar el PDF. */
  preview: (id: string) =>
    api.get<{ html: string; title: string }>(`/reports/${id}/preview`).then((r) => r.data),

  remove: (id: string) => api.delete(`/reports/${id}`).then((r) => r.data),

  /** Descarga el PDF (respeta el JWT) y dispara la descarga en el navegador. */
  download: async (id: string, title: string) => {
    const res = await api.get(`/reports/${id}/download`, { responseType: 'blob' });
    const url = URL.createObjectURL(res.data as Blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${title.replace(/[^\w.-]+/g, '_').slice(0, 60)}.pdf`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },
};
