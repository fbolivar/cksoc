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
