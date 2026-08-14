/**
 * Copiloto flotante global (HUD): botón + panel de chat disponible en toda la
 * app. Usa la API real del copiloto (con herramientas). Se oculta en /copiloto.
 */
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { useLocation } from 'react-router-dom';
import { AxiosError } from 'axios';
import { Bot, Send, Loader2, X, Sparkles } from 'lucide-react';
import { copilotApi, TOOL_LABEL, type ChatMessage } from '@/lib/copilot';
import { useAuth } from '@/lib/auth';

type Msg = ChatMessage & { toolsUsed?: string[] };
const QUICK = ['¿Qué priorizo hoy?', 'Resume el estado del SOC', '¿Qué incidentes tengo abiertos?'];

function renderInline(text: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  const re = /(\*\*([^*]+)\*\*|`([^`]+)`)/g;
  let last = 0; let m: RegExpExecArray | null; let i = 0;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) nodes.push(text.slice(last, m.index));
    if (m[2] != null) nodes.push(<strong key={i} className="text-primary">{m[2]}</strong>);
    else if (m[3] != null) nodes.push(<code key={i} className="rounded bg-secondary/70 px-1 text-[0.85em]">{m[3]}</code>);
    last = m.index + m[0].length; i++;
  }
  if (last < text.length) nodes.push(text.slice(last));
  return nodes;
}

export function CopilotDock() {
  const { user } = useAuth();
  const loc = useLocation();
  const [open, setOpen] = useState(false);
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [messages, setMessages] = useState<Msg[]>([]);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const endRef = useRef<HTMLDivElement>(null);

  const canUse = user?.role === 'admin' || user?.role === 'analista';

  useEffect(() => { if (open && enabled === null) copilotApi.status().then((s) => setEnabled(s.enabled)).catch(() => setEnabled(false)); }, [open, enabled]);
  useEffect(() => { endRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages, busy, open]);

  // No mostrar en la propia página del copiloto, ni a lectores.
  if (loc.pathname === '/copiloto' || !canUse) return null;

  const send = async (text: string) => {
    const msg = text.trim();
    if (!msg || busy) return;
    const history = messages.slice(-8);
    setMessages((m) => [...m, { role: 'user', content: msg }]);
    setInput('');
    setBusy(true);
    try {
      const { reply, toolsUsed } = await copilotApi.chat(msg, history);
      setMessages((m) => [...m, { role: 'assistant', content: reply, toolsUsed }]);
    } catch (e) {
      const em = (e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo consultar el copiloto';
      setMessages((m) => [...m, { role: 'assistant', content: `⚠️ ${em}` }]);
    } finally { setBusy(false); }
  };

  return (
    <>
      {open && (
        <div className="hw-clip fixed bottom-[88px] right-5 z-[55] flex w-[min(370px,92vw)] flex-col border border-primary/25 bg-card shadow-2xl" style={{ boxShadow: '0 0 50px hsl(var(--primary)/.15), 0 24px 60px hsl(var(--ink)/.4)' }}>
          <div className="flex items-center gap-2.5 border-b border-border px-4 py-3">
            <span className="hw-clip flex h-7 w-7 items-center justify-center text-white" style={{ background: 'linear-gradient(140deg, hsl(var(--primary)), hsl(var(--cyan)))' }}><Sparkles className="h-4 w-4" /></span>
            <div className="flex-1 leading-tight">
              <p className="text-[13px] font-semibold">Copiloto IA</p>
              <p className="hw-mono flex items-center gap-1.5 text-[10px]" style={{ color: enabled === false ? 'hsl(var(--warn-orange))' : 'hsl(var(--success))' }}>
                <span className="h-1.5 w-1.5 rounded-full" style={{ background: 'currentColor' }} />{enabled === false ? 'no configurado' : 'en línea'}
              </p>
            </div>
            <button onClick={() => setOpen(false)} className="text-muted-foreground hover:text-foreground" aria-label="Cerrar"><X className="h-4 w-4" /></button>
          </div>

          <div className="flex max-h-[46vh] min-h-[180px] flex-col gap-2.5 overflow-y-auto p-3.5">
            {enabled === false && (
              <p className="rounded-lg border border-warn-orange/30 bg-warn-orange/[0.06] p-2.5 text-[12px] text-warn-orange">El copiloto no está activo: falta configurar la API key en el servidor.</p>
            )}
            {messages.length === 0 && enabled !== false && (
              <div className="m-auto max-w-[240px] text-center">
                <Bot className="mx-auto mb-2 h-8 w-8 text-primary/50" />
                <p className="mb-2.5 text-[12px] text-muted-foreground">Pregúntame sobre tus alertas, incidentes o cómo responder.</p>
                <div className="flex flex-col gap-1.5">
                  {QUICK.map((qq) => <button key={qq} onClick={() => void send(qq)} className="hw-mono rounded-md border border-border px-2.5 py-1.5 text-left text-[11px] hover:border-primary/50 hover:text-primary">{qq}</button>)}
                </div>
              </div>
            )}
            {messages.map((m, i) => (
              <div key={i} className={m.role === 'user' ? 'flex justify-end' : 'flex justify-start'}>
                <div className={m.role === 'user'
                  ? 'hw-clip max-w-[85%] bg-primary px-3 py-2 text-[12.5px] text-primary-foreground'
                  : 'hw-clip max-w-[90%] border border-border bg-secondary/40 px-3 py-2 text-[12.5px]'}>
                  {m.role === 'user' ? m.content : (
                    <div className="space-y-1 leading-relaxed">
                      {m.content.split('\n').map((ln, k) => {
                        const bullet = /^\s*[-*]\s+/.test(ln);
                        if (!ln.trim()) return <div key={k} className="h-1" />;
                        return <div key={k} className={bullet ? 'flex gap-1.5 pl-1' : ''}>{bullet && <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-current opacity-60" />}<span>{renderInline(bullet ? ln.replace(/^\s*[-*]\s+/, '') : ln)}</span></div>;
                      })}
                      {m.toolsUsed && m.toolsUsed.length > 0 && (
                        <p className="hw-mono mt-1.5 border-t border-border/60 pt-1.5 text-[9.5px] text-muted-foreground">🔧 {[...new Set(m.toolsUsed)].map((t) => TOOL_LABEL[t] ?? t).join(', ')}</p>
                      )}
                    </div>
                  )}
                </div>
              </div>
            ))}
            {busy && <div className="flex justify-start"><div className="hw-clip flex items-center gap-2 border border-border bg-secondary/40 px-3 py-2 text-[12px] text-muted-foreground"><Loader2 className="h-3.5 w-3.5 animate-spin" /> pensando…</div></div>}
            <div ref={endRef} />
          </div>

          <div className="border-t border-border p-2.5">
            <div className="flex items-end gap-2">
              <textarea
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); void send(input); } }}
                placeholder={enabled === false ? 'copiloto no configurado' : 'escribe tu pregunta…'}
                disabled={enabled === false || busy}
                rows={1}
                className="max-h-24 min-h-[2.25rem] flex-1 resize-none rounded-lg border border-border bg-background px-3 py-2 text-[12.5px] outline-none focus:border-primary/50 disabled:opacity-50"
              />
              <button onClick={() => void send(input)} disabled={!input.trim() || busy || enabled === false} className="hw-clip flex h-9 w-9 items-center justify-center bg-primary text-primary-foreground disabled:opacity-40" aria-label="Enviar"><Send className="h-4 w-4" /></button>
            </div>
          </div>
        </div>
      )}

      <button
        onClick={() => setOpen((o) => !o)}
        className="hw-clip fixed bottom-5 right-5 z-[55] flex h-14 w-14 items-center justify-center text-white transition-transform hover:scale-105"
        style={{ background: 'linear-gradient(145deg, hsl(var(--primary)), hsl(var(--primary)/.75))', boxShadow: '0 0 30px hsl(var(--primary)/.5)' }}
        aria-label="Copiloto IA"
      >
        {open ? <X className="h-6 w-6" /> : <Bot className="h-6 w-6" />}
      </button>
    </>
  );
}
