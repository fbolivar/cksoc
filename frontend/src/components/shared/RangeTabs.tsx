/** Selector de rango reutilizable (segmented control). */
interface RangeTabsProps<T extends string> {
  value: T;
  onChange: (v: T) => void;
  options: { value: T; label: string }[];
}

export function RangeTabs<T extends string>({ value, onChange, options }: RangeTabsProps<T>) {
  return (
    <div className="inline-flex rounded-lg border border-border/70 bg-card/50 p-1">
      {options.map((o) => (
        <button
          key={o.value}
          onClick={() => onChange(o.value)}
          className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
            value === o.value ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:text-foreground'
          }`}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

/** Opciones estándar 24h / 7d / 30d. */
export const RANGE_24_7_30 = [
  { value: '24h' as const, label: '24 h' },
  { value: '7d' as const, label: '7 días' },
  { value: '30d' as const, label: '30 días' },
];
