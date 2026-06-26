/**
 * Tira compacta de "Salud del SIEM" para el panel principal: semaforo global +
 * un chip por componente, con enlace al panel completo. Resume (no duplica) la
 * pagina de Salud del SIEM.
 */
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { HeartPulse, ChevronRight } from 'lucide-react';
import { healthApi, type SiemHealth, type Estado } from '@/lib/health';
import { Card, CardContent } from '@/components/ui/card';

const DOT: Record<Estado, string> = { ok: 'bg-emerald-500', warn: 'bg-amber-500', fail: 'bg-red-500' };
const SEM: Record<string, { dot: string; txt: string }> = {
  verde: { dot: 'bg-emerald-500', txt: 'SIEM operativo' },
  amarillo: { dot: 'bg-amber-500', txt: 'SIEM con advertencias' },
  rojo: { dot: 'bg-red-500 animate-pulse', txt: 'SIEM con fallos' },
};

export function SiemHealthStrip() {
  const [h, setH] = useState<SiemHealth | null>(null);

  useEffect(() => {
    let alive = true;
    const load = () => healthApi.siem().then((d) => alive && setH(d)).catch(() => undefined);
    load();
    const t = setInterval(load, 60_000);
    return () => { alive = false; clearInterval(t); };
  }, []);

  const sem = h ? SEM[h.semaforo] : SEM.verde;

  return (
    <Link to="/salud" className="block group">
      <Card className="transition-colors hover:border-primary/40">
        <CardContent className="flex flex-wrap items-center gap-x-5 gap-y-2 p-4">
          <div className="flex items-center gap-2.5">
            <HeartPulse className="h-5 w-5 text-neon" />
            <span className={`h-2.5 w-2.5 rounded-full ${sem.dot}`} />
            <span className="font-medium">{sem.txt}</span>
          </div>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-muted-foreground">
            {(h?.componentes ?? []).map((c) => (
              <span key={c.id} className="inline-flex items-center gap-1.5">
                <span className={`h-2 w-2 rounded-full ${DOT[c.estado]}`} />
                {c.nombre.replace(' Wazuh', '').replace(' del Indexer', '').replace(' (clúster)', '')}: {c.resumen.split(' · ')[0].replace(' (normal en clúster de un nodo)', '')}
              </span>
            ))}
          </div>
          <span className="ml-auto inline-flex items-center gap-1 text-xs text-neon opacity-0 transition-opacity group-hover:opacity-100">
            Ver detalle <ChevronRight className="h-3 w-3" />
          </span>
        </CardContent>
      </Card>
    </Link>
  );
}
