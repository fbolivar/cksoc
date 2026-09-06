/** Tipos y API de Asset 360 (vista por activo). */
import { api } from './api';

export type AssetKind = 'servidor' | 'estacion';
export type AssetHealth = 'ok' | 'apagado' | 'investigar' | 'alerta' | 'fantasma';

export interface AssetListItem {
  id: string; name: string; status: string; ip: string; os: string; version: string; lastKeepAlive: string | null;
  kind: AssetKind; staleDays: number | null; health: AssetHealth; reason: string; needsAttention: boolean;
}

export interface AssetCoverage {
  total: number;
  reporting: number;
  servers: { total: number; reporting: number };
  workstations: { total: number; reporting: number };
  needsAttention: AssetListItem[];
  offNormal: number;
}

export interface AssetDetail {
  meta: AssetListItem;
  alertas: { total7d: number; critica: number; alta: number; media: number; baja: number; topReglas: { desc: string; count: number }[] };
  vulnerabilidades: { total: number; criticas: number; altas: number; top: { cve: string; severity: string; score: number | null }[] };
  hardening: { policy: string; score: number; pass: number; fail: number } | null;
  fim: { total30d: number; added: number; modified: number; deleted: number; recientes: { path: string; event: string; user: string; ts: string }[] };
  inventario: { cpu: string; cores: number; ramGB: number; packages: number; ports: number; users: number; hotfixes: number } | null;
}

export const assetsApi = {
  list: () => api.get<{ assets: AssetListItem[]; coverage: AssetCoverage }>('/assets').then((r) => r.data),
  get: (name: string) => api.get<AssetDetail>(`/assets/${encodeURIComponent(name)}`).then((r) => r.data),
};
