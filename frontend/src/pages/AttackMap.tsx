/**
 * Pagina del Mapa de Ataques (geolocalizacion de IPs atacantes).
 * Mapa mundial + arcos a Bogota + Top origenes + tiempo real (WebSocket).
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import { AxiosError } from 'axios';
import { Globe2, Radio, RefreshCw, AlertTriangle, MapPin, ShieldBan, Loader2, CheckCircle2, ShieldCheck } from 'lucide-react';
import {
  attacksApi,
  CLASIF,
  type AttackOrigin,
  type Destination,
  type NewAttack,
} from '@/lib/attacks';
import { responseApi, type ResponseStatus } from '@/lib/response';
import { useAuth } from '@/lib/auth';
import { getSocket } from '@/lib/socket';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { WorldAttackMap } from '@/components/attacks/WorldAttackMap';

type Range = '24h' | '7d' | '30d';
const HOURS: Record<Range, number> = { '24h': 24, '7d': 168, '30d': 720 };

/** Clave de ubicacion para deduplicar origenes (historicos + en vivo). */
function locKey(lat: number, lon: number, iso: string): string {
  return `${iso}|${lat.toFixed(1)},${lon.toFixed(1)}`;
}

interface LiveItem extends NewAttack {
  _id: number;
}

export default function AttackMap() {
  type Filtro = 'todos' | 'externos' | 'usuarios';
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';
  const [range, setRange] = useState<Range>('7d');
  const [filtro, setFiltro] = useState<Filtro>('todos');
  const [threatIntel, setThreatIntel] = useState(true);
  const [origins, setOrigins] = useState<AttackOrigin[]>([]);
  // Bloqueo desde el mapa (reutiliza el modulo de Respuesta)
  const [resp, setResp] = useState<ResponseStatus | null>(null);
  const [blockTarget, setBlockTarget] = useState<AttackOrigin | null>(null);
  const [motivo, setMotivo] = useState('');
  const [blocking, setBlocking] = useState(false);
  const [blockedIps, setBlockedIps] = useState<Set<string>>(new Set());
  const [toast, setToast] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);
  const canBlock = isAdmin && Boolean(resp?.configured && resp?.connection.ok);

  const flash = (kind: 'ok' | 'err', text: string) => {
    setToast({ kind, text });
    setTimeout(() => setToast(null), 5000);
  };

  function openBlock(o: AttackOrigin) {
    setMotivo(
      `Bloqueo desde mapa de ataques · ${CLASIF[o.clasificacion].label}` +
        `${o.abuseScore ? ` (${o.abuseScore}% AbuseIPDB)` : ''} · ${o.country}${o.city ? ' · ' + o.city : ''}`
    );
    setBlockTarget(o);
  }

  async function confirmBlock() {
    if (!blockTarget) return;
    const ip = blockTarget.ips[0];
    setBlocking(true);
    try {
      await responseApi.block(ip, motivo.trim() || 'Bloqueo manual desde mapa de ataques');
      setBlockedIps((prev) => new Set(prev).add(ip));
      flash('ok', `IP ${ip} bloqueada en FortiGate`);
      setBlockTarget(null);
    } catch (e) {
      flash('err', (e as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo bloquear la IP');
    } finally {
      setBlocking(false);
    }
  }
  const [destination, setDestination] = useState<Destination>({ name: 'Bogotá', lat: 4.711, lon: -74.0721 });
  const [live, setLive] = useState<LiveItem[]>([]);
  const [seenLive, setSeenLive] = useState<AttackOrigin[]>([]);
  const [liveCount, setLiveCount] = useState(0);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const liveId = useRef(0);

  async function load(r: Range) {
    setLoading(true);
    setError(null);
    try {
      const data = await attacksApi.geo(HOURS[r]);
      setOrigins(data.origins);
      setDestination(data.destination);
      setThreatIntel(data.threatIntel);
    } catch (err) {
      setError((err as AxiosError<{ error?: string }>).response?.data?.error ?? 'No se pudo cargar el mapa');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load(range);
  }, [range]);

  // Estado del modulo de Respuesta (para habilitar el bloqueo desde el mapa)
  useEffect(() => {
    if (isAdmin) responseApi.status().then(setResp).catch(() => undefined);
  }, [isAdmin]);

  // Tiempo real
  useEffect(() => {
    const socket = getSocket();
    const onConnect = () => setConnected(true);
    const onDisconnect = () => setConnected(false);
    const onAttack = (a: NewAttack) => {
      const id = ++liveId.current;
      setLive((prev) => [...prev.slice(-7), { ...a, _id: id }]);
      setLiveCount((c) => c + 1);
      // El arco brillante desaparece tras 6s
      setTimeout(() => setLive((prev) => prev.filter((x) => x._id !== id)), 6000);
      // El origen se acumula de forma persistente (para que el mapa se re-encuadre
      // y el punto permanezca aunque el arco se desvanezca).
      setSeenLive((prev) => {
        const key = locKey(a.lat, a.lon, a.isoCode);
        const idx = prev.findIndex((o) => locKey(o.lat, o.lon, o.isoCode) === key);
        if (idx >= 0) {
          const cp = [...prev];
          const o = { ...cp[idx] };
          o.count += 1;
          o.severity_max = Math.max(o.severity_max, a.severity);
          o.last_seen = a.ts;
          if (!o.ips.includes(a.ip)) o.ips = [a.ip, ...o.ips].slice(0, 5);
          cp[idx] = o;
          return cp;
        }
        return [
          ...prev,
          {
            country: a.country, city: a.city, isoCode: a.isoCode,
            lat: a.lat, lon: a.lon, count: 1, severity_max: a.severity,
            last_seen: a.ts, ips: [a.ip],
            isp: null, usageType: null, abuseScore: 0,
            clasificacion: 'desconocido' as const, esExterno: false,
          },
        ];
      });
    };
    socket.on('connect', onConnect);
    socket.on('disconnect', onDisconnect);
    socket.on('new_attack', onAttack);
    if (socket.connected) setConnected(true);
    return () => {
      socket.off('connect', onConnect);
      socket.off('disconnect', onDisconnect);
      socket.off('new_attack', onAttack);
    };
  }, []);

  // Origenes mostrados: historicos (/geo) + en vivo (acumulados), sin duplicar.
  const displayOrigins = useMemo(() => {
    const keys = new Set(origins.map((o) => locKey(o.lat, o.lon, o.isoCode)));
    const extra = seenLive.filter((o) => !keys.has(locKey(o.lat, o.lon, o.isoCode)));
    return [...origins, ...extra];
  }, [origins, seenLive]);

  // Conteos por clasificacion y origenes filtrados segun el filtro activo.
  const nExternos = useMemo(() => displayOrigins.filter((o) => o.esExterno).length, [displayOrigins]);
  const nUsuarios = useMemo(
    () => displayOrigins.filter((o) => o.clasificacion === 'usuario').length,
    [displayOrigins]
  );
  const shownOrigins = useMemo(() => {
    if (filtro === 'externos') return displayOrigins.filter((o) => o.esExterno);
    if (filtro === 'usuarios') return displayOrigins.filter((o) => o.clasificacion === 'usuario');
    return displayOrigins;
  }, [displayOrigins, filtro]);

  const totalAttacks = shownOrigins.reduce((s, o) => s + o.count, 0);

  return (
    <div className="mx-auto max-w-7xl space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
            <Globe2 className="h-6 w-6 text-neon" /> Mapa de ataques
          </h1>
          <p className="flex items-center gap-2 text-sm text-muted-foreground">
            Orígenes geolocalizados de IPs atacantes hacia PNNC
            <span
              className="inline-flex items-center gap-1 text-[11px]"
              style={{ color: connected ? 'hsl(var(--neon-green))' : '#9ca3af' }}
            >
              <Radio className="h-3 w-3" />
              {connected ? 'En vivo' : 'Sin conexión'}
            </span>
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="inline-flex rounded-lg border border-border/70 bg-card/50 p-1">
            {(['24h', '7d', '30d'] as Range[]).map((r) => (
              <button
                key={r}
                onClick={() => setRange(r)}
                className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
                  range === r ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:text-foreground'
                }`}
              >
                {r === '24h' ? '24 h' : r === '7d' ? '7 días' : '30 días'}
              </button>
            ))}
          </div>
          <Button variant="outline" size="sm" onClick={() => load(range)} disabled={loading}>
            <RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} />
            Actualizar
          </Button>
        </div>
      </div>

      {/* Filtro por clasificacion (reputacion + tipo de red, no severidad) */}
      {!error && (
        <div className="flex flex-wrap items-center gap-2">
          {([
            ['todos', 'Todos'],
            ['externos', 'Ataques externos'],
            ['usuarios', 'Usuarios VPN'],
          ] as [Filtro, string][]).map(([f, label]) => (
            <button
              key={f}
              onClick={() => setFiltro(f)}
              className={`rounded-full border px-3 py-1.5 text-xs font-medium transition-colors ${
                filtro === f
                  ? 'border-primary/50 bg-primary/15 text-foreground'
                  : 'border-border/60 text-muted-foreground hover:text-foreground'
              }`}
            >
              {label}
              {f === 'externos' && <span className="ml-1.5 text-amber-400">{nExternos}</span>}
              {f === 'usuarios' && <span className="ml-1.5 text-emerald-400">{nUsuarios}</span>}
            </button>
          ))}
          <span className="ml-auto text-[11px] text-muted-foreground/70">
            {threatIntel
              ? 'Clasificado por reputación (AbuseIPDB) + tipo de red, no por severidad de regla'
              : 'Reputación no configurada (AbuseIPDB) — clasificación limitada'}
          </span>
        </div>
      )}

      {error ? (
        <Card>
          <CardContent className="flex items-start gap-3 p-4">
            <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-400" />
            <div className="text-sm">
              <p className="font-medium text-amber-200">Mapa no disponible</p>
              <p className="mt-1 text-muted-foreground">{error}</p>
            </div>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4 lg:grid-cols-3">
          {/* Mapa */}
          <div className="lg:col-span-2">
            <WorldAttackMap origins={shownOrigins} destination={destination} live={live} />
            <div className="mt-2 flex flex-wrap gap-4 px-1 text-[11px] text-muted-foreground">
              <span>{shownOrigins.length} orígenes</span>
              <span>{totalAttacks.toLocaleString('es-CO')} ataques</span>
              {liveCount > 0 && <span className="text-neon">{liveCount} en vivo esta sesión</span>}
              <span className="ml-auto flex items-center gap-3">
                <Legend color={CLASIF.malicioso.color} label="Malicioso" />
                <Legend color={CLASIF.sospechoso.color} label="Sospechoso" />
                <Legend color={CLASIF.usuario.color} label="Usuario" />
                <Legend color={CLASIF.desconocido.color} label="Sin datos" />
              </span>
            </div>
          </div>

          {/* Top origenes */}
          <Card className="h-fit">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-muted-foreground">
                <MapPin className="h-4 w-4" /> Top orígenes de ataque
              </CardTitle>
            </CardHeader>
            <CardContent>
              {shownOrigins.length === 0 ? (
                <p className="py-4 text-center text-sm text-muted-foreground">
                  {filtro === 'externos'
                    ? 'Ningún ataque externo real en este periodo. El IPS del firewall bloquea esas IPs en el perímetro antes de que generen eventos.'
                    : 'Sin orígenes con IP pública en este periodo'}
                </p>
              ) : (
                <div className="space-y-2.5">
                  {shownOrigins.slice(0, 14).map((o, i) => (
                    <div key={i} className="flex items-center gap-2.5">
                      <span className="w-4 text-xs text-muted-foreground/60">{i + 1}</span>
                      <span
                        className="h-2.5 w-2.5 shrink-0 rounded-full"
                        style={{ background: CLASIF[o.clasificacion].color }}
                        title={CLASIF[o.clasificacion].label}
                      />
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm">
                          {o.country}
                          {o.city ? <span className="text-muted-foreground"> · {o.city}</span> : ''}
                        </p>
                        <p className="truncate text-[10px] text-muted-foreground/60">
                          {o.ips[0]}
                          {o.isp ? ` · ${o.isp}` : ''}
                        </p>
                        <p className="truncate text-[10px]" style={{ color: CLASIF[o.clasificacion].color }}>
                          {CLASIF[o.clasificacion].label}
                          {o.usageType ? ` · ${o.usageType}` : ''}
                          {o.abuseScore > 0 ? ` · ${o.abuseScore}%` : ''}
                        </p>
                      </div>
                      <span className="tabular-nums text-sm font-medium">{o.count}</span>
                      {canBlock && (
                        blockedIps.has(o.ips[0]) ? (
                          <span className="inline-flex items-center gap-1 text-[10px] text-emerald-400" title="IP bloqueada">
                            <ShieldCheck className="h-3.5 w-3.5" />
                          </span>
                        ) : (
                          <button
                            onClick={() => openBlock(o)}
                            title={`Bloquear ${o.ips[0]} en FortiGate`}
                            className="rounded-md p-1 text-muted-foreground/60 transition-colors hover:bg-red-500/10 hover:text-red-400"
                          >
                            <ShieldBan className="h-4 w-4" />
                          </button>
                        )
                      )}
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {/* Toast de resultado del bloqueo */}
      {toast && (
        <div
          className={`fixed bottom-5 right-5 z-50 max-w-sm rounded-lg border px-4 py-3 text-sm shadow-2xl ${
            toast.kind === 'ok'
              ? 'border-emerald-500/40 bg-emerald-950/90 text-emerald-200'
              : 'border-destructive/50 bg-red-950/90 text-red-200'
          }`}
        >
          {toast.text}
        </div>
      )}

      {/* Confirmacion de bloqueo desde el mapa */}
      {blockTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={() => !blocking && setBlockTarget(null)}>
          <div className="w-full max-w-md rounded-lg border border-border/70 bg-card shadow-2xl" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center gap-3 border-b border-border/60 px-5 py-4">
              <ShieldBan className="h-5 w-5 text-red-400" />
              <h3 className="font-semibold">Bloquear IP en FortiGate</h3>
            </div>
            <div className="space-y-3 p-5">
              <div className="rounded-md border border-border/60 bg-secondary/40 p-3 text-sm">
                <div className="flex items-center gap-2 font-medium">
                  <span className="h-2.5 w-2.5 rounded-full" style={{ background: CLASIF[blockTarget.clasificacion].color }} />
                  {blockTarget.ips[0]}
                  <span className="text-xs" style={{ color: CLASIF[blockTarget.clasificacion].color }}>
                    {CLASIF[blockTarget.clasificacion].label}
                  </span>
                </div>
                <p className="mt-1 text-xs text-muted-foreground">
                  {blockTarget.country}{blockTarget.city ? ` · ${blockTarget.city}` : ''}
                  {blockTarget.isp ? ` · ${blockTarget.isp}` : ''}
                  {blockTarget.usageType ? ` · ${blockTarget.usageType}` : ''}
                  {` · reputación ${blockTarget.abuseScore}%`}
                </p>
              </div>

              {blockTarget.clasificacion === 'usuario' && (
                <div className="flex items-start gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-100">
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
                  Esta IP está clasificada como <b>Usuario</b> (ISP residencial, reputación limpia): probablemente un empleado legítimo. Verifica antes de bloquear.
                </div>
              )}

              <div className="space-y-1.5">
                <label className="text-xs text-muted-foreground">Motivo (queda en auditoría)</label>
                <Textarea value={motivo} onChange={(e) => setMotivo(e.target.value)} className="min-h-[70px] text-sm" />
              </div>

              <p className="text-[11px] text-muted-foreground">
                Se añadirá a la lista de bloqueo del FortiGate. La lista blanca y la auditoría se aplican en el servidor.
              </p>

              <div className="flex justify-end gap-2">
                <Button variant="outline" onClick={() => setBlockTarget(null)} disabled={blocking}>Cancelar</Button>
                <Button onClick={confirmBlock} disabled={blocking} className="bg-red-600 text-white hover:bg-red-500">
                  {blocking ? <Loader2 className="h-4 w-4 animate-spin" /> : <CheckCircle2 className="h-4 w-4" />} Confirmar bloqueo
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function Legend({ color, label }: { color: string; label: string }) {
  return (
    <span className="flex items-center gap-1">
      <span className="h-2 w-2 rounded-full" style={{ background: color }} />
      {label}
    </span>
  );
}
