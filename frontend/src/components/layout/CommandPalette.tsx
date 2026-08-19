/**
 * Command palette global (Ctrl/⌘-K): busca y salta a cualquier vista del SOC.
 * Se abre con el atajo o con el evento 'hw-open-palette' (botón de búsqueda).
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, CornerDownLeft } from 'lucide-react';

interface Cmd { label: string; to: string; sec: string }
const COMMANDS: Cmd[] = [
  { label: 'Command Center', to: '/', sec: 'VISTA' },
  { label: 'Resumen Ejecutivo', to: '/resumen', sec: 'VISTA' },
  { label: 'Copiloto IA', to: '/copiloto', sec: 'VISTA' },
  { label: 'Métricas SOC', to: '/metricas', sec: 'VISTA' },
  { label: 'Alertas', to: '/alertas', sec: 'DETECTAR' },
  { label: 'Detecciones', to: '/deteccion', sec: 'DETECTAR' },
  { label: 'MITRE ATT&CK', to: '/mitre', sec: 'DETECTAR' },
  { label: 'Comportamiento · UEBA', to: '/comportamiento', sec: 'DETECTAR' },
  { label: 'Riesgo por entidad', to: '/riesgo-entidad', sec: 'DETECTAR' },
  { label: 'Correlación', to: '/correlacion', sec: 'DETECTAR' },
  { label: 'Mapa de ataques', to: '/mapa', sec: 'DETECTAR' },
  { label: 'NDR · Red', to: '/ndr', sec: 'DETECTAR' },
  { label: 'Office 365', to: '/office365', sec: 'DETECTAR' },
  { label: 'Threat Hunting', to: '/hunting', sec: 'INVESTIGAR' },
  { label: 'Threat Intelligence', to: '/threat-intel', sec: 'INVESTIGAR' },
  { label: 'Velociraptor · DFIR', to: '/velociraptor', sec: 'INVESTIGAR' },
  { label: 'Incidentes', to: '/incidentes', sec: 'RESPONDER' },
  { label: 'Respuesta · FortiGate', to: '/respuesta', sec: 'RESPONDER' },
  { label: 'Automatización · SOAR', to: '/soar', sec: 'RESPONDER' },
  { label: 'Activos', to: '/activos', sec: 'POSTURA' },
  { label: 'Vulnerabilidades', to: '/vulnerabilidades', sec: 'POSTURA' },
  { label: 'Hardening CIS (SCA)', to: '/sca', sec: 'POSTURA' },
  { label: 'Integridad (FIM)', to: '/fim', sec: 'POSTURA' },
  { label: 'IT Hygiene', to: '/hygiene', sec: 'POSTURA' },
  { label: 'Factor humano', to: '/factor-humano', sec: 'POSTURA' },
  { label: 'Cumplimiento normativo', to: '/cumplimiento', sec: 'POSTURA' },
  { label: 'Reportes', to: '/reportes', sec: 'OPERACIÓN' },
  { label: 'Notificaciones', to: '/notificaciones', sec: 'OPERACIÓN' },
  { label: 'On-call · Turnos', to: '/oncall', sec: 'OPERACIÓN' },
  { label: 'Salud del SIEM', to: '/salud', sec: 'OPERACIÓN' },
  { label: 'Auditoría', to: '/auditoria', sec: 'OPERACIÓN' },
  { label: 'Gestión de usuarios', to: '/gestion', sec: 'OPERACIÓN' },
];

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState('');
  const [sel, setSel] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  const results = useMemo(() => {
    const s = q.trim().toLowerCase();
    const list = s ? COMMANDS.filter((c) => c.label.toLowerCase().includes(s) || c.sec.toLowerCase().includes(s)) : COMMANDS;
    return list.slice(0, 10);
  }, [q]);

  useEffect(() => { setSel(0); }, [q]);

  const openPalette = useCallback(() => { setOpen(true); setQ(''); setTimeout(() => inputRef.current?.focus(), 20); }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setOpen((o) => !o); if (!open) setTimeout(() => inputRef.current?.focus(), 20); }
      else if (e.key === 'Escape') setOpen(false);
    };
    const onEvt = () => openPalette();
    window.addEventListener('keydown', onKey);
    window.addEventListener('hw-open-palette', onEvt);
    return () => { window.removeEventListener('keydown', onKey); window.removeEventListener('hw-open-palette', onEvt); };
  }, [open, openPalette]);

  const go = (c: Cmd) => { setOpen(false); navigate(c.to); };

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-[60] flex items-start justify-center pt-[12vh]" style={{ background: 'hsl(var(--ink) / .5)', backdropFilter: 'blur(4px)' }} onClick={() => setOpen(false)}>
      <div className="hw-clip w-[min(560px,92vw)] border border-primary/30 bg-card shadow-2xl" style={{ boxShadow: '0 0 60px hsl(var(--primary)/.18), 0 30px 80px hsl(var(--ink)/.5)' }} onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-2 border-b border-border px-4">
          <Search className="h-4 w-4 text-muted-foreground" />
          <input
            ref={inputRef}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'ArrowDown') { e.preventDefault(); setSel((s) => Math.min(s + 1, results.length - 1)); }
              else if (e.key === 'ArrowUp') { e.preventDefault(); setSel((s) => Math.max(s - 1, 0)); }
              else if (e.key === 'Enter') { e.preventDefault(); if (results[sel]) go(results[sel]); }
            }}
            placeholder="buscar vistas del SOC…"
            className="hw-mono w-full bg-transparent py-4 text-[15px] text-foreground outline-none placeholder:text-muted-foreground"
          />
          <span className="hw-mono hidden items-center gap-1 text-[10px] text-muted-foreground sm:flex"><CornerDownLeft className="h-3 w-3" /> ir</span>
        </div>
        <div className="max-h-[340px] overflow-y-auto p-2">
          {results.length === 0 ? (
            <p className="hw-mono px-3 py-6 text-center text-sm text-muted-foreground">Sin resultados.</p>
          ) : results.map((c, i) => (
            <button
              key={c.to}
              onMouseEnter={() => setSel(i)}
              onClick={() => go(c)}
              className={`hw-mono flex w-full items-center gap-3 rounded-md px-3 py-2.5 text-left text-[13px] ${i === sel ? 'bg-primary/12 text-primary' : 'text-foreground/80'}`}
            >
              <span className="text-primary">›</span>
              <span className="flex-1 truncate">{c.label}</span>
              <span className="text-[9.5px] tracking-widest text-muted-foreground">{c.sec}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
