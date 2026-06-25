/**
 * Generadores de graficas como SVG embebido (sin librerias ni JS en el PDF).
 * Se usan en la plantilla HTML que Puppeteer convierte a PDF.
 */

const fmt = (n: number) => n.toLocaleString('es-CO');
const esc = (s: string) =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

/** Donut de severidad. data: [{label,value,color}] */
export function donutSvg(
  data: { label: string; value: number; color: string }[],
  size = 180
): string {
  const total = data.reduce((s, d) => s + d.value, 0) || 1;
  const r = size / 2;
  const inner = r * 0.62;
  const cx = r;
  const cy = r;
  let angle = -Math.PI / 2;
  const arcs = data
    .filter((d) => d.value > 0)
    .map((d) => {
      const frac = d.value / total;
      const a0 = angle;
      const a1 = angle + frac * 2 * Math.PI;
      angle = a1;
      const large = frac > 0.5 ? 1 : 0;
      const x0 = cx + r * Math.cos(a0);
      const y0 = cy + r * Math.sin(a0);
      const x1 = cx + r * Math.cos(a1);
      const y1 = cy + r * Math.sin(a1);
      const xi1 = cx + inner * Math.cos(a1);
      const yi1 = cy + inner * Math.sin(a1);
      const xi0 = cx + inner * Math.cos(a0);
      const yi0 = cy + inner * Math.sin(a0);
      return `<path d="M ${x0} ${y0} A ${r} ${r} 0 ${large} 1 ${x1} ${y1} L ${xi1} ${yi1} A ${inner} ${inner} 0 ${large} 0 ${xi0} ${yi0} Z" fill="${d.color}"/>`;
    })
    .join('');
  return `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" xmlns="http://www.w3.org/2000/svg">
    ${arcs}
    <text x="${cx}" y="${cy - 4}" text-anchor="middle" font-size="22" font-weight="700" fill="#0f3d24">${fmt(total)}</text>
    <text x="${cx}" y="${cy + 16}" text-anchor="middle" font-size="11" fill="#6b7c74">total</text>
  </svg>`;
}

/** Barras horizontales. data: [{label,value}] */
export function barsSvg(
  data: { label: string; value: number }[],
  color = '#1f7a4d',
  width = 480
): string {
  if (data.length === 0) return '<p style="color:#888">Sin datos</p>';
  const max = Math.max(...data.map((d) => d.value)) || 1;
  const rowH = 26;
  const labelW = 150;
  const barW = width - labelW - 70;
  const height = data.length * rowH;
  const rows = data
    .map((d, i) => {
      const w = Math.max(2, (d.value / max) * barW);
      const y = i * rowH;
      return `
      <text x="${labelW - 8}" y="${y + 17}" text-anchor="end" font-size="11" fill="#33413b">${esc(
        d.label.length > 24 ? d.label.slice(0, 23) + '…' : d.label
      )}</text>
      <rect x="${labelW}" y="${y + 5}" width="${w}" height="16" rx="3" fill="${color}" opacity="${1 - i * 0.06}"/>
      <text x="${labelW + w + 6}" y="${y + 17}" font-size="11" fill="#33413b">${fmt(d.value)}</text>`;
    })
    .join('');
  return `<svg width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" xmlns="http://www.w3.org/2000/svg">${rows}</svg>`;
}

/** Mini grafica de area (timeline). data: [{ts,count}] */
export function sparkAreaSvg(
  data: { ts: string; count: number }[],
  width = 760,
  height = 140,
  color = '#1f7a4d'
): string {
  if (data.length < 2) return '<p style="color:#888">Sin datos suficientes</p>';
  const max = Math.max(...data.map((d) => d.count)) || 1;
  const stepX = width / (data.length - 1);
  const pts = data.map((d, i) => {
    const x = i * stepX;
    const y = height - (d.count / max) * (height - 20) - 4;
    return [x, y] as const;
  });
  const line = pts.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p[0].toFixed(1)} ${p[1].toFixed(1)}`).join(' ');
  const area = `${line} L ${width} ${height} L 0 ${height} Z`;
  return `<svg width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" xmlns="http://www.w3.org/2000/svg">
    <path d="${area}" fill="${color}" opacity="0.15"/>
    <path d="${line}" fill="none" stroke="${color}" stroke-width="2"/>
    <text x="2" y="12" font-size="10" fill="#6b7c74">pico: ${fmt(max)}</text>
  </svg>`;
}
