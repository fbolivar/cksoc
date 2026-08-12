/**
 * Centro de notificaciones (campanita) en la Topbar.
 * Carga las notificaciones recientes (/notifications/log) y se suscribe al
 * evento socket 'notification:new' para mostrarlas en vivo. Las "no leídas"
 * son las posteriores a la última vez que se abrió el panel (localStorage).
 */
import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Bell, Loader2 } from 'lucide-react';
import { getSocket } from '@/lib/socket';
import { fetchFeed, linkFor, type FeedItem, type LiveNotification } from '@/lib/notifyFeed';

const SEEN_KEY = 'soc_notif_last_seen';

function timeAgo(iso: string): string {
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return 'hace un momento';
  if (s < 3600) return `hace ${Math.floor(s / 60)} min`;
  if (s < 86400) return `hace ${Math.floor(s / 3600)} h`;
  return new Date(iso).toLocaleDateString('es-CO', { day: '2-digit', month: 'short' });
}

export function NotificationBell() {
  const [items, setItems] = useState<FeedItem[]>([]);
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(true);
  const [lastSeen, setLastSeen] = useState<number>(() => Number(localStorage.getItem(SEEN_KEY) ?? 0));
  const ref = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();

  const openItem = (link: string) => {
    setOpen(false);
    navigate(link);
  };

  useEffect(() => {
    fetchFeed()
      .then(setItems)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    const socket = getSocket();
    const onNew = (n: LiveNotification) => {
      setItems((prev) => [
        {
          id: `live-${n.at}-${Math.random().toString(36).slice(2, 7)}`,
          title: n.ruleName || (n.origen ? `Alerta · ${n.origen}` : 'Notificación'),
          status: n.status,
          createdAt: n.at,
          link: linkFor({ origen: n.origen }),
          live: true,
        },
        ...prev,
      ].slice(0, 50));
    };
    socket.on('notification:new', onNew);
    return () => {
      socket.off('notification:new', onNew);
    };
  }, []);

  // Cerrar al hacer clic fuera
  useEffect(() => {
    if (!open) return;
    const onClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onClick);
    return () => document.removeEventListener('mousedown', onClick);
  }, [open]);

  const unread = items.filter((i) => new Date(i.createdAt).getTime() > lastSeen).length;

  const toggle = () => {
    const next = !open;
    setOpen(next);
    if (next) {
      const now = Date.now();
      localStorage.setItem(SEEN_KEY, String(now));
      setLastSeen(now);
    }
  };

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={toggle}
        className="relative rounded-md p-2 text-white/80 transition-colors hover:bg-white/10 hover:text-white"
        title="Notificaciones"
        aria-label="Notificaciones"
      >
        <Bell className="h-4 w-4" />
        {unread > 0 && (
          <span className="absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-destructive px-1 text-[10px] font-bold text-white">
            {unread > 9 ? '9+' : unread}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 z-50 mt-2 w-80 overflow-hidden rounded-lg border border-border bg-card shadow-2xl">
          <div className="flex items-center justify-between border-b border-border/60 px-4 py-2.5">
            <span className="text-sm font-semibold text-foreground">Notificaciones</span>
            <span className="text-[11px] text-muted-foreground">{items.length} recientes</span>
          </div>
          <div className="max-h-96 overflow-y-auto">
            {loading ? (
              <div className="flex items-center justify-center p-6 text-muted-foreground">
                <Loader2 className="h-4 w-4 animate-spin" />
              </div>
            ) : items.length === 0 ? (
              <div className="p-6 text-center text-sm text-muted-foreground">Sin notificaciones.</div>
            ) : (
              items.map((it) => {
                const isUnread = new Date(it.createdAt).getTime() > lastSeen;
                return (
                  <button
                    key={it.id}
                    onClick={() => openItem(it.link)}
                    className={`flex w-full items-start gap-2 border-b border-border/40 px-4 py-2.5 text-left text-sm transition-colors hover:bg-secondary ${isUnread ? 'bg-primary/5' : ''}`}
                    title="Ver en Alertas"
                  >
                    <span
                      className={`mt-1 h-2 w-2 shrink-0 rounded-full ${
                        it.status === 'sent' ? 'bg-primary' : it.status === 'failed' ? 'bg-destructive' : 'bg-muted-foreground/40'
                      }`}
                    />
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-foreground">{it.title}</p>
                      <p className="text-[11px] text-muted-foreground">
                        {timeAgo(it.createdAt)}
                        {it.status === 'failed' ? ' · falló el envío' : it.status === 'skipped' ? ' · omitida' : ''}
                      </p>
                    </div>
                  </button>
                );
              })
            )}
          </div>
          <button
            onClick={() => openItem('/notificaciones')}
            className="block w-full border-t border-border/60 px-4 py-2 text-center text-xs text-brand hover:underline"
          >
            Ver todas las notificaciones
          </button>
        </div>
      )}
    </div>
  );
}
