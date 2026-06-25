import type { LucideIcon } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { cn } from '@/lib/utils';
import { fmt } from './theme';

interface Props {
  title: string;
  value: number | string;
  icon: LucideIcon;
  accent?: string; // color hex del icono/acento
  live?: boolean;
  subtitle?: string;
}

export function MetricCard({ title, value, icon: Icon, accent, live, subtitle }: Props) {
  return (
    <Card className="relative overflow-hidden">
      <CardContent className="p-5">
        <div className="flex items-start justify-between">
          <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            {title}
          </p>
          <Icon className="h-4 w-4" style={{ color: accent ?? 'hsl(var(--neon-green))' }} />
        </div>
        <div className="mt-2 flex items-end gap-2">
          <span className="text-3xl font-bold tabular-nums" style={{ color: accent }}>
            {typeof value === 'number' ? fmt(value) : value}
          </span>
          {live && (
            <span className="mb-1 flex items-center gap-1 text-[10px] text-neon">
              <span className={cn('h-1.5 w-1.5 rounded-full bg-neon animate-pulse-soft')} />
              EN VIVO
            </span>
          )}
        </div>
        {subtitle && <p className="mt-1 text-xs text-muted-foreground">{subtitle}</p>}
      </CardContent>
    </Card>
  );
}
