import { useMemo } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import type { TimelinePoint } from '@/lib/wazuh';
import { fmt } from './theme';

const DAYS = ['Dom', 'Lun', 'Mar', 'Mie', 'Jue', 'Vie', 'Sab'];

/**
 * Mapa de calor de actividad: dia de la semana (filas) x hora del dia (columnas).
 * Recibe puntos horarios (range=7d, interval=1h) y los agrega.
 */
export function ActivityHeatmap({ data }: { data: TimelinePoint[] }) {
  const { grid, max } = useMemo(() => {
    const g: number[][] = Array.from({ length: 7 }, () => Array(24).fill(0));
    let m = 0;
    for (const p of data) {
      const d = new Date(p.ts);
      const day = d.getDay();
      const hour = d.getHours();
      g[day][hour] += p.count;
      if (g[day][hour] > m) m = g[day][hour];
    }
    return { grid: g, max: m };
  }, [data]);

  // Escala de color: verde con opacidad proporcional (escala log para suavizar picos)
  const color = (v: number): string => {
    if (v === 0) return 'rgba(255,255,255,0.04)';
    const intensity = Math.log(v + 1) / Math.log(max + 1);
    return `hsl(145 70% 45% / ${0.15 + intensity * 0.85})`;
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-muted-foreground">
          Mapa de calor de actividad · ultimos 7 dias (hora × dia)
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto">
          <div className="min-w-[640px]">
            {/* Cabecera de horas */}
            <div className="flex pl-10">
              {Array.from({ length: 24 }, (_, h) => (
                <div key={h} className="flex-1 text-center text-[9px] text-muted-foreground/60">
                  {h % 3 === 0 ? h : ''}
                </div>
              ))}
            </div>
            {/* Filas por dia */}
            {grid.map((row, day) => (
              <div key={day} className="flex items-center">
                <div className="w-10 pr-2 text-right text-[10px] text-muted-foreground">
                  {DAYS[day]}
                </div>
                {row.map((v, h) => (
                  <div
                    key={h}
                    className="flex-1 aspect-square m-[1px] rounded-sm"
                    style={{ background: color(v) }}
                    title={`${DAYS[day]} ${h}:00 — ${fmt(v)} alertas`}
                  />
                ))}
              </div>
            ))}
          </div>
        </div>
        <div className="mt-3 flex items-center justify-end gap-2 text-[10px] text-muted-foreground">
          <span>Menos</span>
          {[0.04, 0.3, 0.55, 0.8, 1].map((o, i) => (
            <span
              key={i}
              className="h-3 w-3 rounded-sm"
              style={{ background: `hsl(145 70% 45% / ${o})` }}
            />
          ))}
          <span>Más</span>
        </div>
      </CardContent>
    </Card>
  );
}
