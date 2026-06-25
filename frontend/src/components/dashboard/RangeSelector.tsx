import type { TimeRange } from '@/lib/wazuh';
import { cn } from '@/lib/utils';

const OPTIONS: { value: TimeRange; label: string }[] = [
  { value: '24h', label: '24 h' },
  { value: '7d', label: '7 dias' },
  { value: '30d', label: '30 dias' },
];

export function RangeSelector({
  value,
  onChange,
}: {
  value: TimeRange;
  onChange: (r: TimeRange) => void;
}) {
  return (
    <div className="inline-flex rounded-lg border border-border/70 bg-card/50 p-1">
      {OPTIONS.map((o) => (
        <button
          key={o.value}
          onClick={() => onChange(o.value)}
          className={cn(
            'rounded-md px-3 py-1.5 text-xs font-medium transition-colors',
            value === o.value
              ? 'bg-primary text-primary-foreground'
              : 'text-muted-foreground hover:text-foreground'
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}
