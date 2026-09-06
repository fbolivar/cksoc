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

export interface RecoveryPosture {
  estado: 'ok' | 'warn' | 'fail';
  totalBackups: number;
  lastBackupAt: string | null;
  lastBackupAgeHours: number | null;
  fresh: boolean;
  totalBytes: number;
  retention: number;
  cron: string;
  integrity: { ok: number; corrupto: number; desconocida: number };
  offsite: boolean;
  location: string;
  scope: string;
  warnings: string[];
}

export const backupsApi = {
  list: () => api.get<{ backups: BackupItem[] }>('/backups').then((r) => r.data.backups),
  posture: () => api.get<RecoveryPosture>('/backups/posture').then((r) => r.data),

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
