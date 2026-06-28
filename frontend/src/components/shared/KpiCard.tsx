/** Tarjeta KPI reutilizable. Formatea numeros en es-CO; los strings se muestran tal cual. */
import { type LucideIcon } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';

export function KpiCard({
  label, value, color, icon: Icon,
}: {
  label: string;
  value: string | number;
  color?: string;
  icon?: LucideIcon;
}) {
  const display = typeof value === 'number' ? value.toLocaleString('es-CO') : value;
  return (
    <Card>
      <CardContent className="p-4">
        <div className="flex items-center justify-between">
          <span className="text-xs text-muted-foreground">{label}</span>
          {Icon && <Icon className="h-4 w-4 text-muted-foreground" />}
        </div>
        <p className="mt-1 text-2xl font-semibold tabular-nums" style={color ? { color } : undefined}>
          {display}
        </p>
      </CardContent>
    </Card>
  );
}
