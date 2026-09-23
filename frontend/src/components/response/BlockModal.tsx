/** Modal de confirmacion de bloqueo (accion destructiva, claramente diferenciada). */
import { useState, type FormEvent } from 'react';
import { ShieldX, AlertTriangle, Loader2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';

/** Detecta IP interna en el cliente (defensa en profundidad; el backend tambien valida). */
function isInternal(ip: string): boolean {
  const p = ip.split('.').map(Number);
  if (p.length !== 4) return false;
  if (p[0] === 10 || p[0] === 127) return true;
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
  if (p[0] === 192 && p[1] === 168) return true;
  return false;
}

export function BlockModal({
  ip,
  context,
  group,
  onConfirm,
  onCancel,
}: {
  ip: string;
  context?: string; // descripcion del incidente
  group?: string;
  onConfirm: (motivo: string) => Promise<void>;
  onCancel: () => void;
}) {
  const [motivo, setMotivo] = useState(context ? `Fuerza bruta: ${context}` : '');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const internal = isInternal(ip);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await onConfirm(motivo);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'No se pudo bloquear');
      setLoading(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onCancel}>
      <div
        className="w-full max-w-md rounded-lg border border-red-500/40 bg-card shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-3 border-b border-red-500/30 bg-red-500/10 px-5 py-4">
          <ShieldX className="h-6 w-6 text-red-400" />
          <div>
            <h3 className="font-semibold text-red-200">Confirmar bloqueo de IP</h3>
            <p className="text-xs text-muted-foreground">Acción sobre el SonicWall · quedará registrada</p>
          </div>
        </div>

        <form onSubmit={submit} className="space-y-4 p-5">
          <div className="rounded-md border border-border/60 bg-background/40 p-3 text-sm">
            <p>
              Vas a bloquear la IP <span className="font-bold text-red-600">{ip}</span> en el SonicWall
              {group ? <> (grupo <span className="font-mono text-xs">{group}</span>)</> : ''}.
            </p>
            <p className="mt-1 text-xs text-muted-foreground">
              Se añadirá a la lista de denegación. Podrás revertirlo desde “IPs bloqueadas”.
            </p>
          </div>

          {internal && (
            <div className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
              <span className="text-amber-700">
                Esta IP parece <b>interna</b>. El sistema la rechazará: no se puede bloquear infraestructura interna.
              </span>
            </div>
          )}

          <div className="space-y-2">
            <Label htmlFor="motivo">Motivo (obligatorio, queda en auditoría)</Label>
            <Textarea
              id="motivo"
              value={motivo}
              onChange={(e) => setMotivo(e.target.value)}
              required
              minLength={3}
              placeholder="Ej: Fuerza bruta VPN sostenida, IP reportada en AbuseIPDB"
            />
          </div>

          {error && (
            <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {error}
            </div>
          )}

          <div className="flex justify-end gap-2">
            <Button type="button" variant="outline" onClick={onCancel} disabled={loading}>
              Cancelar
            </Button>
            <Button
              type="submit"
              variant="destructive"
              disabled={loading || internal || motivo.trim().length < 3}
            >
              {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldX className="h-4 w-4" />}
              {loading ? 'Bloqueando…' : 'Confirmar bloqueo'}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}
