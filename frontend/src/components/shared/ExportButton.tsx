/** Boton reutilizable para exportar a CSV (con estado de carga). */
import { Download, Loader2 } from 'lucide-react';
import { Button } from '@/components/ui/button';

export function ExportButton({
  onExport,
  disabled,
  busy,
  label = 'CSV',
}: {
  onExport: () => void;
  disabled?: boolean;
  busy?: boolean;
  label?: string;
}) {
  return (
    <Button variant="outline" size="sm" onClick={onExport} disabled={disabled || busy} title="Exportar a CSV">
      {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
      {label}
    </Button>
  );
}
