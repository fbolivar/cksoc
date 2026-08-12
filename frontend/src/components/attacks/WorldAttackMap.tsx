/**
 * Mapa mundial de ataques (react-simple-maps), estetica oscura SOC.
 * - Paises en gris-azul, oceano oscuro, Colombia resaltada.
 * - Un punto pulsante por origen (color por severidad, tamano por nº de ataques).
 * - Arcos animados desde cada origen hacia Bogota (destino PNNC).
 * - Arcos "en vivo" para ataques recibidos por WebSocket.
 */
import { useMemo, useState } from 'react';
import { ComposableMap, Geographies, Geography, Marker } from 'react-simple-maps';
import { geoEqualEarth } from 'd3-geo';
import type { AttackOrigin, Destination, NewAttack } from '@/lib/attacks';
import { CLASIF } from '@/lib/attacks';

const W = 980;
const H = 520;
const PAD = 60; // margen al encuadrar los puntos
const MAX_SCALE = 1100; // tope de acercamiento (evita zoom excesivo si todo esta junto)
const GEO_URL = '/world-110m.json';

function markerRadius(count: number): number {
  return Math.max(3.5, Math.min(15, 3 + Math.sqrt(count) * 1.7));
}

export function WorldAttackMap({
  origins,
  destination,
  live,
}: {
  origins: AttackOrigin[];
  destination: Destination;
  live: NewAttack[];
}) {
  const [hover, setHover] = useState<{ o: AttackOrigin; x: number; y: number } | null>(null);

  // Proyeccion con AUTO-FIT: encuadra todos los origenes (+ ataques en vivo)
  // y el destino. Se ajusta sola segun donde esten los atacantes.
  // La misma instancia alimenta el mapa y el dibujo de los arcos.
  const projection = useMemo(() => {
    const pts: [number, number][] = [
      ...origins.map((o) => [o.lon, o.lat] as [number, number]),
      ...live.map((a) => [a.lon, a.lat] as [number, number]),
      [destination.lon, destination.lat],
    ];
    const proj = geoEqualEarth().translate([W / 2, H / 2]);
    if (pts.length <= 1) return proj.scale(168).center([0, 12]);

    const lons = pts.map((p) => p[0]);
    const lats = pts.map((p) => p[1]);
    const minLon = Math.min(...lons), maxLon = Math.max(...lons);
    const minLat = Math.min(...lats), maxLat = Math.max(...lats);
    const centroid: [number, number] = [(minLon + maxLon) / 2, (minLat + maxLat) / 2];
    const span = Math.max(maxLon - minLon, maxLat - minLat);

    // Si todos los puntos estan muy juntos, usar zoom maximo centrado.
    if (span < 2) return proj.center(centroid).scale(MAX_SCALE);

    const fc = {
      type: 'FeatureCollection',
      features: pts.map((c) => ({ type: 'Feature', geometry: { type: 'Point', coordinates: c }, properties: {} })),
    };
    proj.fitExtent([[PAD, PAD], [W - PAD, H - PAD]], fc as never);
    // Tope de acercamiento
    if (proj.scale() > MAX_SCALE) {
      const c = (proj.invert?.([W / 2, H / 2]) as [number, number]) ?? centroid;
      proj.scale(MAX_SCALE).center(c).translate([W / 2, H / 2]);
    }
    return proj;
  }, [origins, live, destination]);

  const project = (lon: number, lat: number): [number, number] | null => {
    const p = projection([lon, lat]);
    return p ? [p[0], p[1]] : null;
  };

  const dest = project(destination.lon, destination.lat);

  const arcPath = (lon: number, lat: number): string | null => {
    const a = project(lon, lat);
    if (!a || !dest) return null;
    const [x1, y1] = a;
    const [x2, y2] = dest;
    const dx = x2 - x1;
    const dy = y2 - y1;
    const dist = Math.hypot(dx, dy) || 1;
    const nx = -dy / dist;
    const ny = dx / dist;
    const bow = 0.28;
    const cx = (x1 + x2) / 2 + nx * dist * bow;
    const cy = (y1 + y2) / 2 + ny * dist * bow;
    return `M ${x1} ${y1} Q ${cx} ${cy} ${x2} ${y2}`;
  };

  return (
    <div className="relative w-full overflow-hidden rounded-lg border border-border/60 bg-[#0a1410]">
      <ComposableMap
        width={W}
        height={H}
        projection={projection as never}
        style={{ width: '100%', height: 'auto' }}
      >
        <Geographies geography={GEO_URL}>
          {({ geographies }: { geographies: { rsmKey: string; properties: { name?: string } }[] }) =>
            geographies.map((geo) => {
              const isColombia = geo.properties.name === 'Colombia';
              return (
                <Geography
                  key={geo.rsmKey}
                  geography={geo as never}
                  fill={isColombia ? '#16472f' : '#1b2a33'}
                  stroke={isColombia ? '#34d399' : '#2b3b44'}
                  strokeWidth={isColombia ? 0.8 : 0.4}
                  style={{
                    default: { outline: 'none' },
                    hover: { outline: 'none', fill: isColombia ? '#16472f' : '#243640' },
                    pressed: { outline: 'none' },
                  }}
                />
              );
            })
          }
        </Geographies>

        {/* Arcos persistentes (origenes agregados) */}
        <g fill="none">
          {origins.map((o, i) => {
            const d = arcPath(o.lon, o.lat);
            if (!d) return null;
            return (
              <path
                key={`arc-${i}`}
                d={d}
                stroke={CLASIF[o.clasificacion].color}
                strokeWidth={0.9}
                strokeOpacity={0.55}
                className="attack-arc"
              />
            );
          })}
          {/* Arcos en vivo (WebSocket) */}
          {live.map((a, i) => {
            const d = arcPath(a.lon, a.lat);
            if (!d) return null;
            return (
              <path
                key={`live-${a.ip}-${i}`}
                d={d}
                stroke="#7dffff"
                strokeWidth={1.6}
                strokeOpacity={0.95}
                style={{ ['--len' as string]: '600', strokeDasharray: 600 } as React.CSSProperties}
                className="attack-arc-live"
              />
            );
          })}
        </g>

        {/* Puntos de origen */}
        {origins.map((o, i) => {
          const r = markerRadius(o.count);
          const color = CLASIF[o.clasificacion].color;
          return (
            <Marker key={`m-${i}`} coordinates={[o.lon, o.lat]}>
              <circle r={r} fill={color} opacity={0.35} className="attack-ping" />
              <circle
                r={r * 0.55}
                fill={color}
                stroke="#fff"
                strokeWidth={0.6}
                style={{ cursor: 'pointer' }}
                onMouseEnter={() => {
                  const p = project(o.lon, o.lat);
                  if (p) setHover({ o, x: (p[0] / W) * 100, y: (p[1] / H) * 100 });
                }}
                onMouseLeave={() => setHover(null)}
              />
            </Marker>
          );
        })}

        {/* Destino: Bogota */}
        <Marker coordinates={[destination.lon, destination.lat]}>
          <circle r={6} fill="none" stroke="#34d399" strokeWidth={1.5} className="attack-ping" />
          <circle r={3} fill="#34d399" />
          <text textAnchor="middle" y={-10} fill="#9fe9c5" fontSize={9} fontWeight={600}>
            HexWatch · Bogotá
          </text>
        </Marker>
      </ComposableMap>

      {/* Tooltip */}
      {hover && (
        <div
          className="pointer-events-none absolute z-10 -translate-x-1/2 -translate-y-full rounded-md border border-border/70 bg-card/95 px-3 py-2 text-xs shadow-lg backdrop-blur"
          style={{ left: `${hover.x}%`, top: `${hover.y}%` }}
        >
          <div className="flex items-center gap-1.5 font-semibold">
            <span className="h-2 w-2 rounded-full" style={{ background: CLASIF[hover.o.clasificacion].color }} />
            {hover.o.country}
            {hover.o.city ? ` · ${hover.o.city}` : ''}
            <span className="text-[10px] font-normal" style={{ color: CLASIF[hover.o.clasificacion].color }}>
              {CLASIF[hover.o.clasificacion].label}
            </span>
          </div>
          <div className="text-muted-foreground">
            {hover.o.count.toLocaleString('es-CO')} eventos
            {hover.o.isp ? ` · ${hover.o.isp}` : ''}
          </div>
          <div className="text-[10px] text-muted-foreground/70">
            {hover.o.usageType ?? 'tipo de red desconocido'}
            {hover.o.abuseScore > 0 ? ` · reputación ${hover.o.abuseScore}%` : ' · reputación 0%'}
          </div>
          <div className="text-[10px] text-muted-foreground/70">{hover.o.ips.slice(0, 3).join(', ')}</div>
          <div className="text-[10px] text-muted-foreground/70">
            Últ.: {hover.o.last_seen ? new Date(hover.o.last_seen).toLocaleString('es-CO') : '—'}
          </div>
        </div>
      )}
    </div>
  );
}
