/** Cliente de on-call (turnos de guardia). */
import { api } from './api';

export interface Shift {
  id: string;
  userId: string;
  userName: string;
  userEmail: string;
  startsAt: string;
  endsAt: string;
  note: string | null;
  createdBy: string | null;
}

export interface EscalationResult { delivered: boolean; to: string[]; onCall: string | null; reason: string }

export const oncallApi = {
  list: (from?: string, to?: string) => api.get<{ shifts: Shift[] }>('/oncall', { params: { from, to } }).then((r) => r.data.shifts),
  current: () => api.get<{ current: Shift | null }>('/oncall/current').then((r) => r.data.current),
  create: (input: { userId: string; startsAt: string; endsAt: string; note?: string }) => api.post<Shift>('/oncall', input).then((r) => r.data),
  remove: (id: string) => api.delete(`/oncall/${id}`).then((r) => r.data),
  test: () => api.post<EscalationResult>('/oncall/test').then((r) => r.data),
};
