/** Cliente de respaldos de base de datos (.pnnc). Solo admin. */
import { api } from './api';

export interface BackupItem {
  id: string;
  createdAt: string;
  origin: 'manual' | 'automatico';
  note: string | null;
  fileBytes: number;
  uncompressedBytes: number;
  integrity: 'ok' | 'corrupto' | 'desconocida';
}

export const backupsApi = {
  list: () => api.get<{ backups: BackupItem[] }>('/backups').then((r) => r.data.backups),

  create: (note?: string) =>
    api.post<BackupItem>('/backups', { note: note || undefined }).then((r) => r.data),

  verify: (id: string) =>
    api.get<{ integrity: 'ok' | 'corrupto' }>(`/backups/${encodeURIComponent(id)}/verify`).then((r) => r.data.integrity),

  remove: (id: string) => api.delete(`/backups/${encodeURIComponent(id)}`).then((r) => r.data),

  download: async (id: string) => {
    const res = await api.get(`/backups/${encodeURIComponent(id)}/download`, { responseType: 'blob' });
    const url = URL.createObjectURL(res.data as Blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = id;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },
};
