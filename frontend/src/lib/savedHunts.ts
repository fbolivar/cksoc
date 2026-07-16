/** Cliente de cacerías guardadas (saved hunts). */
import { api } from './api';
import type { HuntQuery } from './hunt';

export interface SavedHunt {
  id: string;
  name: string;
  query: HuntQuery;
  alertEnabled: boolean;
  threshold: number;
  intervalMin: number;
  lastRun: string | null;
  lastCount: number | null;
  createdAt: string;
}

export const savedHuntsApi = {
  list: () => api.get<{ hunts: SavedHunt[] }>('/hunt/saved').then((r) => r.data.hunts),
  create: (data: { name: string; query: HuntQuery; alertEnabled?: boolean; threshold?: number; intervalMin?: number }) =>
    api.post<SavedHunt>('/hunt/saved', data).then((r) => r.data),
  update: (id: string, data: Partial<{ name: string; query: HuntQuery; alertEnabled: boolean; threshold: number; intervalMin: number }>) =>
    api.put<SavedHunt>(`/hunt/saved/${id}`, data).then((r) => r.data),
  remove: (id: string) => api.delete(`/hunt/saved/${id}`).then((r) => r.data),
  run: (id: string) => api.post<{ total: number }>(`/hunt/saved/${id}/run`, {}).then((r) => r.data),
};
