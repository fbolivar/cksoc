/**
 * Render mínimo de Markdown para las respuestas de IA: encabezados, **negrita**,
 * `código` y viñetas, preservando saltos de línea y espaciado entre párrafos.
 * Suficiente para el formato que produce el Copiloto (no es un parser completo).
 */
import { type ReactNode } from 'react';

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

export function Markdownish({ text }: { text: string }) {
  return (
    <div className="space-y-1 text-sm leading-relaxed">
      {text.split('\n').map((line, idx) => {
        const t = line.trimEnd();
        if (!t) return <div key={idx} className="h-2" />;
        const h = /^(#{1,6})\s+(.*)$/.exec(t);
        if (h) return <div key={idx} className="mt-1.5 text-[13px] font-semibold uppercase tracking-wide text-foreground/90">{renderInline(h[2], `h${idx}`)}</div>;
        const bullet = /^\s*[-*]\s+/.test(t);
        if (bullet) return (
          <div key={idx} className="flex gap-2 pl-1">
            <span className="mt-[7px] h-1 w-1 shrink-0 rounded-full bg-current opacity-60" />
            <span>{renderInline(t.replace(/^\s*[-*]\s+/, ''), `l${idx}`)}</span>
          </div>
        );
        return <div key={idx}>{renderInline(t, `l${idx}`)}</div>;
      })}
    </div>
  );
}
