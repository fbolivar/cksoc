/** Tipos y API de Asset 360 (vista por activo). */
import { api } from './api';

export interface AssetListItem {
  id: string; name: string; status: string; ip: string; os: string; version: string; lastKeepAlive: string | null;
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
  list: () => api.get<{ assets: AssetListItem[] }>('/assets').then((r) => r.data.assets),
  get: (name: string) => api.get<AssetDetail>(`/assets/${encodeURIComponent(name)}`).then((r) => r.data),
};
