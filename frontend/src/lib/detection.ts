/** Gestión de detecciones: reglas ruidosas y supresión de falsos positivos. */
import { api } from './api';

export interface NoisyRule {
  ruleId: string;
  description: string;
  level: number;
  count: number;
  groups: string[];
}

export interface Suppression {
  id: number;
  targetRuleId: string;
  field: string;
  value: string;
  comment: string;
}

export const detectionApi = {
  noisy: (range: string) =>
    api.get<{ range: string; rules: NoisyRule[] }>('/detection/noisy', { params: { range } }).then((r) => r.data.rules),
  suppressions: () =>
    api.get<{ fields: string[]; suppressions: Suppression[] }>('/detection/suppressions').then((r) => r.data),
  addSuppression: (body: { targetRuleId: string; field: string; value: string; comment: string }) =>
    api.post<Suppression>('/detection/suppressions', body).then((r) => r.data),
  removeSuppression: (id: number) =>
    api.delete(`/detection/suppressions/${id}`).then((r) => r.data),
};
