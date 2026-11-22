import { useState } from 'react';
import { MailWarning, Search, Loader2, AlertTriangle, Trash2, CheckCircle2 } from 'lucide-react';
import { clawbackApi, type ClawPreview, type Criteria } from '@/lib/clawback';

export default function Clawback() {
  const [sender, setSender] = useState('');
  const [subject, setSubject] = useState('');
  const [imid, setImid] = useState('');
  const [days, setDays] = useState(7);
  const [prev, setPrev] = useState<ClawPreview | null>(null);
  const [done, setDone] = useState<ClawPreview | null>(null);
  const [busy, setBusy] = useState<'preview' | 'execute' | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [confirmText, setConfirmText] = useState('');

  const crit = (): Criteria => ({ sender: sender.trim() || undefined, subject: subject.trim() || undefined, internetMessageId: imid.trim() || undefined, days });

  async function doPreview() {
    setBusy('preview'); setErr(null); setDone(null); setConfirmText('');
    try { const p = await clawbackApi.preview(crit()); setPrev(p); if (!p.ok) setErr(p.error ?? 'Error'); }
    catch (e) { setErr((e as { response?: { data?: { error?: string } } })?.response?.data?.error ?? 'No se pudo previsualizar'); }
    finally { setBusy(null); }
  }
  async function doExecute() {
    setBusy('execute'); setErr(null);
    try { const r = await clawbackApi.execute(crit()); setDone(r); setPrev(null); setConfirmText(''); if (!r.ok) setErr(r.error ?? 'Error'); }
    catch (e) { setErr((e as { response?: { data?: { error?: string } } })?.response?.data?.error ?? 'No se pudo ejecutar (¿permiso admin?)'); }
    finally { setBusy(null); }
  }

  const input = 'w-full rounded-md border border-border bg-secondary/40 px-3 py-2 text-sm outline-none focus:border-primary';

  return (
    <div className="space-y-5">
      <div>
        <h1 className="flex items-center gap-2 text-xl font-bold"><MailWarning className="h-5 w-5 text-brand" /> Claw-back de correo (M365)</h1>
        <p className="text-sm text-muted-foreground">Localiza un correo malicioso en todos los buzones y lo mueve a Elementos eliminados (reversible). Remediación post-entrega.</p>
      </div>

      <div className="flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-2 text-[11px] text-amber-700">
        <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
        Ejecutar mueve el correo a <b>Elementos eliminados</b> en cada buzón (recuperable por el usuario), solo para administradores. Previsualiza primero y confirma. La acción queda auditada.
      </div>

      <div className="glass space-y-3 rounded-lg p-4">
        <div className="grid gap-2 sm:grid-cols-2">
          <div><label className="text-[11px] text-muted-foreground">Remitente</label><input className={input} value={sender} onChange={(e) => setSender(e.target.value)} placeholder="atacante@dominio.com" /></div>
          <div><label className="text-[11px] text-muted-foreground">Asunto contiene (opcional)</label><input className={input} value={subject} onChange={(e) => setSubject(e.target.value)} placeholder="Factura urgente" /></div>
          <div className="sm:col-span-2"><label className="text-[11px] text-muted-foreground">internetMessageId (opcional, exacto)</label><input className={`${input} font-mono text-xs`} value={imid} onChange={(e) => setImid(e.target.value)} placeholder="<abc123@dominio.com>" /></div>
          <div><label className="text-[11px] text-muted-foreground">Ventana (días)</label><input type="number" min={1} max={30} className={input} value={days} onChange={(e) => setDays(Number(e.target.value))} /></div>
        </div>
        <button onClick={() => void doPreview()} disabled={busy !== null || (!sender.trim() && !imid.trim())} className="inline-flex items-center gap-1 rounded-lg bg-brand px-3 py-1.5 text-xs font-semibold text-white hover:opacity-90 disabled:opacity-50">
          {busy === 'preview' ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />} Previsualizar (solo lectura)
        </button>
      </div>

      {err && <div className="flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-2 text-xs text-amber-600"><AlertTriangle className="h-4 w-4" /> {err}</div>}

      {prev && prev.ok && (
        <div className="glass space-y-3 rounded-lg p-4">
          <p className="text-sm font-semibold">Previsualización: {prev.totalMatches} correo(s) en {prev.afectados} buzón(es) de {prev.mailboxes} escaneados</p>
          {prev.resultados.length === 0 ? <p className="py-4 text-center text-xs text-muted-foreground">No se encontró el correo en ningún buzón.</p> : (
            <>
              <div className="max-h-[300px] space-y-1 overflow-y-auto">
                {prev.resultados.map((r) => (
                  <div key={r.upn} className="rounded bg-secondary/20 px-2.5 py-1.5 text-xs">
                    <div className="flex justify-between"><span className="hw-mono">{r.upn}</span><span className="font-semibold text-red-500">{r.count}</span></div>
                    {r.samples[0] && <p className="truncate text-[10px] text-muted-foreground">{r.samples[0].subject} — {r.samples[0].from}</p>}
                  </div>
                ))}
              </div>
              <div className="rounded-lg border border-red-500/30 bg-red-500/5 p-3">
                <p className="mb-2 text-xs text-muted-foreground">Para ejecutar el claw-back (mover a Elementos eliminados en {prev.afectados} buzón(es)), escribe <b className="text-foreground">CONFIRMAR</b>:</p>
                <div className="flex items-center gap-2">
                  <input className={`${input} max-w-[180px]`} value={confirmText} onChange={(e) => setConfirmText(e.target.value)} placeholder="CONFIRMAR" />
                  <button onClick={() => void doExecute()} disabled={confirmText !== 'CONFIRMAR' || busy !== null} className="inline-flex items-center gap-1 rounded-lg bg-red-600 px-3 py-1.5 text-xs font-semibold text-white hover:opacity-90 disabled:opacity-40">
                    {busy === 'execute' ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />} Ejecutar claw-back
                  </button>
                </div>
              </div>
            </>
          )}
        </div>
      )}

      {done && done.ok && (
        <div className="glass space-y-2 rounded-lg p-4">
          <p className="flex items-center gap-2 text-sm font-semibold text-emerald-600"><CheckCircle2 className="h-4 w-4" /> Claw-back ejecutado: {done.totalMatches} correo(s) movido(s) a Elementos eliminados en {done.afectados} buzón(es)</p>
          <div className="max-h-[300px] space-y-1 overflow-y-auto">
            {done.resultados.map((r) => (
              <div key={r.upn} className="flex justify-between rounded bg-secondary/20 px-2.5 py-1.5 text-xs">
                <span className="hw-mono">{r.upn}</span><span className="font-semibold text-emerald-500">{r.moved ?? 0}/{r.count}{r.error ? ' ⚠' : ''}</span>
              </div>
            ))}
          </div>
          <p className="text-[10px] text-muted-foreground/70">Reversible: los usuarios pueden recuperar desde Elementos eliminados. Acción registrada en auditoría.</p>
        </div>
      )}
    </div>
  );
}
