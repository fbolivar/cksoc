/**
 * Copiloto IA — asistente de análisis del SOC sobre la API de Claude. Chat con
 * contexto en vivo (alertas, incidentes, anomalías UEBA) + acciones rápidas.
 */
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { AxiosError } from 'axios';
import { Sparkles, Send, Loader2, Info, Trash2 } from 'lucide-react';
import { copilotApi, TOOL_LABEL, type ChatMessage } from '@/lib/copilot';

type Msg = ChatMessage & { toolsUsed?: string[] };
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

const QUICK = [
  'Resume el estado del SOC ahora mismo.',
  '¿Qué incidentes tengo abiertos y cuál priorizo?',
  'Prioriza las anomalías de comportamiento (UEBA) abiertas y dime qué revisar primero.',
  '¿Qué reglas están generando más ruido y podrían ser falsos positivos?',
];

/** Render mínimo: **negrita**, `código` y viñetas, preservando saltos de línea. */
function renderInline(text: string, keyBase: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  const re = /(\*\*([^*]+)\*\*|`([^`]+)`)/g;
  let last = 0; let m: RegExpExecArray | null; let i = 0;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) nodes.push(text.slice(last, m.index));
    if (m[2] != null) nodes.push(<strong key={`${keyBase}-b${i}`}>{m[2]}</strong>);
    else if (m[3] != null) nodes.push(<code key={`${keyBase}-c${i}`} className="rounded bg-secondary/70 px-1 text-[0.85em]">{m[3]}</code>);
    last = m.index + m[0].length; i++;
  }
  if (last < text.length) nodes.push(text.slice(last));
  return nodes;
}

function Markdownish({ text }: { text: string }) {
  return (
    <div className="space-y-1 text-sm leading-relaxed">
      {text.split('\n').map((line, idx) => {
        const t = line.trimEnd();
        const bullet = /^\s*[-*]\s+/.test(t);
        if (!t) return <div key={idx} className="h-1.5" />;
        return (
          <div key={idx} className={bullet ? 'flex gap-2 pl-1' : ''}>
            {bullet && <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-current opacity-60" />}
            <span>{renderInline(bullet ? t.replace(/^\s*[-*]\s+/, '') : t, `l${idx}`)}</span>
          </div>
        );
      })}
    </div>
  );
}

export default function Copilot() {
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [messages, setMessages] = useState<Msg[]>([]);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => { copilotApi.status().then((s) => setEnabled(s.enabled)).catch(() => setEnabled(false)); }, []);
  useEffect(() => { endRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages, busy]);

  const send = async (text: string) => {
    const msg = text.trim();
    if (!msg || busy) return;
    setError(null);
    const history = messages.slice(-10);
    setMessages((m) => [...m, { role: 'user', content: msg }]);
    setInput('');
    setBusy(true);
    try {
      const { reply, toolsUsed } = await copilotApi.chat(msg, history);
      setMessages((m) => [...m, { role: 'assistant', content: reply, toolsUsed }]);
    } catch (e) {
      const em = (e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo obtener respuesta del copiloto';
      setError(em);
      setMessages((m) => [...m, { role: 'assistant', content: `⚠️ ${em}` }]);
    } finally { setBusy(false); }
  };

  return (
    <div className="mx-auto flex h-[calc(100vh-7rem)] max-w-3xl flex-col">
      <div className="mb-3 flex items-center justify-between">
        <div>
          <h1 className="flex items-center gap-2 hw-mono text-2xl font-bold tracking-tight">
            <Sparkles className="h-6 w-6 text-neon" /> Copiloto IA
          </h1>
          <p className="text-sm text-muted-foreground">Asistente de análisis con contexto en vivo del SOC</p>
        </div>
        {messages.length > 0 && (
          <Button variant="outline" size="sm" onClick={() => setMessages([])}><Trash2 className="mr-1 h-4 w-4" /> Limpiar</Button>
        )}
      </div>

      {enabled === false && (
        <Card className="mb-3 border-amber-500/30 bg-amber-500/[0.05]">
          <CardContent className="flex items-start gap-2 p-3 text-sm text-amber-700">
            <Info className="mt-0.5 h-4 w-4 shrink-0" />
            <span>El copiloto no está activo: falta configurar <code className="rounded bg-secondary/70 px-1">ANTHROPIC_API_KEY</code> en el servidor. Una vez agregada, este chat funciona. Al usarlo se envía contexto del SOC a la API de Claude (nube).</span>
          </CardContent>
        </Card>
      )}

      <Card className="flex min-h-0 flex-1 flex-col">
        <CardContent className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto p-4">
          {messages.length === 0 ? (
            <div className="m-auto max-w-md text-center">
              <Sparkles className="mx-auto mb-3 h-10 w-10 text-neon/50" />
              <p className="mb-3 text-sm text-muted-foreground">Pregúntame sobre el estado del SOC, una alerta, un incidente o cómo responder a una amenaza.</p>
              <div className="flex flex-col gap-2">
                {QUICK.map((q) => (
                  <button key={q} onClick={() => send(q)} disabled={enabled === false}
                    className="rounded-lg border border-input px-3 py-2 text-left text-xs text-foreground hover:border-neon/40 hover:bg-secondary/40 disabled:opacity-50">
                    {q}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            messages.map((m, i) => (
              <div key={i} className={m.role === 'user' ? 'flex justify-end' : 'flex justify-start'}>
                <div className={m.role === 'user'
                  ? 'max-w-[85%] rounded-2xl rounded-br-sm bg-primary px-4 py-2 text-sm text-primary-foreground'
                  : 'max-w-[90%] rounded-2xl rounded-bl-sm border border-input bg-secondary/30 px-4 py-2.5'}>
                  {m.role === 'user' ? m.content : <Markdownish text={m.content} />}
                  {m.role === 'assistant' && m.toolsUsed && m.toolsUsed.length > 0 && (
                    <p className="mt-1.5 border-t border-input/50 pt-1.5 text-[10px] text-muted-foreground/70">
                      🔧 consultó: {[...new Set(m.toolsUsed)].map((t) => TOOL_LABEL[t] ?? t).join(', ')}
                    </p>
                  )}
                </div>
              </div>
            ))
          )}
          {busy && (
            <div className="flex justify-start">
              <div className="flex items-center gap-2 rounded-2xl rounded-bl-sm border border-input bg-secondary/30 px-4 py-2.5 text-sm text-muted-foreground">
                <Loader2 className="h-4 w-4 animate-spin" /> Pensando…
              </div>
            </div>
          )}
          <div ref={endRef} />
        </CardContent>

        <div className="border-t border-input p-3">
          {error && <p className="mb-2 px-1 text-xs text-amber-700">{error}</p>}
          <div className="flex items-end gap-2">
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); void send(input); } }}
              placeholder={enabled === false ? 'Configura ANTHROPIC_API_KEY para chatear…' : 'Escribe tu pregunta… (Enter para enviar, Shift+Enter salto de línea)'}
              disabled={enabled === false || busy}
              rows={1}
              className="max-h-32 min-h-[2.5rem] flex-1 resize-none rounded-lg border border-input bg-background px-3 py-2 text-sm outline-none focus:border-neon/50 disabled:opacity-50"
            />
            <Button onClick={() => void send(input)} disabled={!input.trim() || busy || enabled === false} size="sm" className="h-10">
              <Send className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </Card>
    </div>
  );
}
