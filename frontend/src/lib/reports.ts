/** Tipos y llamadas a la API de reportes. */
import { api } from './api';
import type { TimeRange } from './wazuh';

export interface Report {
  id: string;
  title: string;
  type: 'manual' | 'scheduled';
  format: string;
  params: { range?: string };
  status: string;
  created_at: string;
}

// ----------------- Reporte ejecutivo mensual -----------------

export interface ExecReportRef {
  id: string;
  mes: string;
  estado: 'borrador' | 'revisado' | 'enviado';
  enviado_en?: string | null;
  generado_en?: string;
}

export interface ExecPreview {
  report: ExecReportRef;
  html: string;
  resumen: string;
  recomendaciones: string;
}

export const executiveApi = {
  generate: (mes: string) =>
    api.post<ExecPreview>('/reports/executive/generate', { mes }).then((r) => r.data),
  get: (id: string) => api.get<ExecPreview>(`/reports/executive/${id}`).then((r) => r.data),
  update: (id: string, data: { resumen?: string; recomendaciones?: string }) =>
    api.put<ExecPreview>(`/reports/executive/${id}`, data).then((r) => r.data),
  send: (id: string) =>
    api.post<{ recipients: string[] }>(`/reports/executive/${id}/send`).then((r) => r.data),
  history: () =>
    api.get<{ reports: ExecReportRef[] }>('/reports/executive/history').then((r) => r.data.reports),
  download: async (id: string, mes: string) => {
    const res = await api.get(`/reports/executive/${id}/download`, { responseType: 'blob' });
    const url = URL.createObjectURL(res.data as Blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Reporte-Ejecutivo-${mes}.pdf`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },
};

export const reportsApi = {
  list: () => api.get<{ reports: Report[] }>('/reports').then((r) => r.data.reports),

  generate: (title: string, range: TimeRange) =>
    api.post<{ report: Report }>('/reports/generate', { title, range }).then((r) => r.data.report),

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
