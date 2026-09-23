/**
 * Plantilla HTML del PARTE DE ESTADO. Documento de una página (A4), con la
 * identidad HexWatch, pensado para convertirse a PDF y enviarse al cliente.
 * Diseño honesto pero vendedor: número grande de throughput, titular de
 * tranquilidad (0 incidentes) y las estaciones en atención a la vista.
 */
import type { ShiftReportData } from './shift-report.data';

const esc = (s: string): string =>
  s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c] as string));
const nf = (n: number): string => new Intl.NumberFormat('es-CO').format(n);

function pct(part: number, total: number): number {
  if (total <= 0) return 0;
  return Math.round((part / total) * 100);
}

export function renderShiftReport(d: ShiftReportData): string {
  const ORG = (process.env.REPORT_ORG_NAME || 'Click Solutions').replace(/&/g,'&amp;');
  const CLIENT = (process.env.REPORT_CLIENT_NAME || 'DG&A ABOGADOS').replace(/&/g,'&amp;');
  const total = d.estaciones || 1;
  const onPct = Math.max(d.wkEnLinea ? 8 : 0, pct(d.wkEnLinea, total));
  const attPct = Math.max(d.wkAtencion ? 8 : 0, pct(d.wkAtencion, total));
  const offPct = Math.max(0, 100 - onPct - attPct);
  const shiftIcon = d.turno === 'am' ? '☀' : '🌇';
  const proximo =
    d.turno === 'am' ? 'Próximo parte: hoy 15:00' : 'Próximo parte: mañana 09:00';

  const critOk = d.incidentesCriticos === 0;
  const heroBig = critOk ? 'OPERACIÓN NORMAL' : 'INCIDENTES EN GESTIÓN';
  const heroSub = critOk
    ? 'Sin incidentes críticos en el turno · Infraestructura protegida y en línea'
    : `${d.incidentesCriticos} incidente(s) crítico(s) detectado(s) y en atención por el SOC`;

  const atencionHtml = d.atencion.length
    ? d.atencion
        .map(
          (a) => `<li class="${a.ghost ? 'ghost' : ''}">
            <div class="host">${esc(a.host)}</div>
            <div class="why">${esc(a.motivo)}</div>
          </li>`
        )
        .join('')
    : `<li class="clean"><div class="host">Sin novedades</div><div class="why">Todas las estaciones activas reportan con normalidad.</div></li>`;

  const sevColor: Record<string, string> = { critica: '#dc2626', alta: '#ea580c', media: '#d97706', baja: '#64748b' };
  const activosHtml = d.equiposActivos.length
    ? d.equiposActivos.map((e) => `<span class="chip on">${esc(e.name)}</span>`).join('')
    : '<span class="muted">Ninguno reportando</span>';
  const inactivosHtml = d.equiposInactivos.length
    ? d.equiposInactivos.map((e) => `<span class="chip off" title="${esc(e.motivo)}">${esc(e.name)}</span>`).join('')
    : '<span class="muted">Ninguno · todos en línea</span>';
  const activasHtml = d.estacionesActivas.length
    ? d.estacionesActivas.map((e) => `<li><span class="hn">${esc(e.host)}</span><span class="ev">${nf(e.eventos)} eventos</span></li>`).join('')
    : '<li><span class="hn">Sin actividad relevante en el turno</span></li>';
  const incidentesHtml = d.topIncidentes.length
    ? d.topIncidentes.map((i) => `<li><span class="sev" style="background:${sevColor[i.severidad] || '#64748b'}"></span><span class="tt">${esc(i.titulo)}</span><span class="meta">${esc(i.severidad)} · ${esc(i.estado)}</span></li>`).join('')
    : '<li class="none">Sin incidentes registrados en el periodo 🟢</li>';
  const amenazasHtml = d.topAmenazas.length
    ? d.topAmenazas.map((a) => `<li><span class="tt">${esc(a.label)}</span><span class="meta">${nf(a.count)}</span></li>`).join('')
    : '<li class="none">Sin amenazas de severidad relevante en el turno 🟢</li>';
  const riesgosCorreoHtml = d.correo.riesgos.length
    ? d.correo.riesgos.map((r) => `<li><span class="sev" style="background:${sevColor[r.severity] || '#64748b'}"></span><span class="tt">${esc(r.label)}</span><span class="meta">${nf(r.count)}</span></li>`).join('')
    : '<li class="none">Sin riesgos de correo/M365 en el turno 🟢</li>';

  return `<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,600;12..96,700;12..96,800&family=Inter+Tight:wght@400;500;600&family=IBM+Plex+Mono:wght@500;600&display=swap">
<style>
  :root{
    --coral:#F0512E; --coral-soft:#FDECE7; --ink:#191C22; --muted:#697086; --faint:#9AA0B0;
    --paper:#FFFFFF; --line:#E6E8EF; --green:#12A150; --green-soft:#E7F6ED;
    --amber:#D68309; --amber-soft:#FBF0DD; --red:#DC3B3B; --slate:#8790A2;
    --disp:'Bricolage Grotesque',system-ui,sans-serif; --body:'Inter Tight',system-ui,sans-serif;
    --mono:'IBM Plex Mono',ui-monospace,monospace;
  }
  @page{size:A4;margin:0}
  *{box-sizing:border-box;margin:0;padding:0}
  html,body{background:#fff;color:var(--ink);font-family:var(--body);line-height:1.45;-webkit-print-color-adjust:exact;print-color-adjust:exact}
  .sheet{width:210mm;min-height:297mm;margin:0 auto;padding:0;display:flex;flex-direction:column}
  .head{position:relative;padding:16mm 16mm 7mm;background:radial-gradient(120% 140% at 100% 0%, #FFF3EF 0%, #FFFFFF 46%);border-bottom:1px solid var(--line)}
  .head::before{content:"";position:absolute;left:0;top:0;bottom:0;width:6px;background:var(--coral)}
  .brand{display:flex;align-items:center;gap:10px}
  .mark{width:32px;height:32px;flex:none}
  .brand h1{font-family:var(--disp);font-weight:800;font-size:20px;letter-spacing:-.02em}
  .brand .tag{font-size:11px;color:var(--coral);font-weight:600;letter-spacing:.08em;text-transform:uppercase;margin-top:1px}
  .head-row{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;margin-top:16px}
  .doc-title{font-family:var(--disp);font-weight:700;font-size:24px;letter-spacing:-.02em;line-height:1.05}
  .doc-sub{font-size:13px;color:var(--muted);margin-top:3px}
  .stamp{text-align:right;font-family:var(--mono);font-size:11.5px;color:var(--muted);line-height:1.7;white-space:nowrap}
  .stamp b{color:var(--ink)}
  .shift-pill{display:inline-flex;align-items:center;gap:6px;font-family:var(--body);font-weight:600;font-size:12px;color:var(--coral);background:var(--coral-soft);padding:4px 11px;border-radius:999px}
  .hero{display:flex;align-items:center;gap:16px;padding:5mm 16mm;background:${critOk ? 'var(--green-soft)' : 'var(--amber-soft)'};border-bottom:1px solid var(--line)}
  .hero .dot{width:13px;height:13px;border-radius:50%;background:${critOk ? 'var(--green)' : 'var(--amber)'};box-shadow:0 0 0 4px ${critOk ? 'rgba(18,161,80,.16)' : 'rgba(214,131,9,.16)'};flex:none}
  .hero .big{font-family:var(--disp);font-weight:800;font-size:20px;letter-spacing:-.01em;color:${critOk ? '#0C7A3B' : '#9A5B06'}}
  .hero .small{font-size:12.5px;color:${critOk ? '#3E7355' : '#7A5A2A'}}
  .hero .right{margin-left:auto;text-align:right;font-size:11.5px;color:${critOk ? '#3E7355' : '#7A5A2A'};font-family:var(--mono)}
  section{padding:6mm 16mm}
  .eyebrow{font-size:11px;font-weight:700;letter-spacing:.11em;text-transform:uppercase;color:var(--faint);margin-bottom:11px}
  .kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:11px}
  .kpi{border:1px solid var(--line);border-radius:12px;padding:13px 14px;position:relative;overflow:hidden}
  .kpi .num{font-family:var(--disp);font-weight:800;font-size:29px;letter-spacing:-.03em;line-height:1;font-variant-numeric:tabular-nums}
  .kpi .lbl{font-size:11px;color:var(--muted);margin-top:7px;line-height:1.3}
  .kpi .win{font-family:var(--mono);font-size:9px;color:var(--faint);text-transform:uppercase;letter-spacing:.05em;margin-top:6px}
  .kpi.accent .num{color:var(--coral)} .kpi.accent{background:linear-gradient(180deg,#FFF7F4,#fff)}
  .kpi.good .num{color:var(--green)}
  .kpi .spark{position:absolute;right:11px;top:12px;font-size:15px}
  .two{display:grid;grid-template-columns:1.15fr .85fr;gap:24px}
  .bar{height:34px;display:flex;border-radius:9px;overflow:hidden;border:1px solid var(--line)}
  .bar span{display:flex;align-items:center;justify-content:center;font-family:var(--mono);font-size:12px;font-weight:600;color:#fff}
  .seg-on{background:var(--green)} .seg-off{background:var(--slate)} .seg-att{background:var(--amber)}
  .legend{display:flex;flex-direction:column;gap:10px;margin-top:15px}
  .lg{display:flex;align-items:center;gap:10px;font-size:13px}
  .lg .sw{width:11px;height:11px;border-radius:3px;flex:none}
  .lg .n{font-family:var(--mono);font-weight:600;margin-left:auto}
  .lg small{color:var(--muted);font-size:11px;display:block;margin-top:1px}
  .att h4{margin:0 0 9px;font-size:12.5px;font-weight:700;display:flex;align-items:center;gap:7px}
  .att h4 .badge{font-family:var(--mono);font-size:10px;background:var(--amber-soft);color:var(--amber);padding:2px 7px;border-radius:6px}
  .att ul{list-style:none;display:flex;flex-direction:column;gap:8px}
  .att li{border:1px solid var(--line);border-left:3px solid var(--amber);border-radius:8px;padding:9px 11px}
  .att li.ghost{border-left-color:var(--slate)} .att li.clean{border-left-color:var(--green)}
  .att .host{font-family:var(--mono);font-size:12.5px;font-weight:600}
  .att .why{font-size:11px;color:var(--muted);margin-top:2px}
  .mgmt{background:#FAFBFC;border-top:1px solid var(--line)}
  .mgmt ul{list-style:none;display:grid;grid-template-columns:1fr 1fr;gap:10px 24px}
  .mgmt li{display:flex;gap:10px;font-size:12.5px;align-items:flex-start}
  .mgmt li .ic{width:19px;height:19px;border-radius:6px;background:var(--green-soft);color:var(--green);display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;flex:none;margin-top:1px}
  footer{margin-top:auto;padding:6mm 16mm;border-top:1px solid var(--line);display:flex;justify-content:space-between;align-items:center;gap:14px}
  .sig{font-size:12px;color:var(--muted)} .sig b{color:var(--ink)}
  .next{font-family:var(--mono);font-size:11.5px;color:var(--coral);background:var(--coral-soft);padding:5px 12px;border-radius:8px}
  .chips{display:flex;flex-wrap:wrap;gap:5px;margin-top:8px}
  .chip{font-family:var(--mono);font-size:10.5px;padding:3px 8px;border-radius:6px;border:1px solid var(--line)}
  .chip.on{background:var(--green-soft);color:var(--green);border-color:transparent}
  .chip.off{background:#F1F5F9;color:var(--muted)}
  .muted{color:var(--muted);font-size:11.5px}
  .hosts-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-top:16px}
  .hosts-grid h5,.active-list h5{margin:0 0 3px;font-size:11.5px;font-weight:700}
  .active-list{margin-top:15px}
  .active-list ol{list-style:none;counter-reset:a;display:flex;flex-direction:column;gap:5px}
  .active-list li{counter-increment:a;display:flex;align-items:center;gap:8px;font-size:12px}
  .active-list li::before{content:counter(a);font-family:var(--mono);font-size:10px;background:#eef2ff;color:#4f46e5;width:16px;height:16px;border-radius:5px;display:flex;align-items:center;justify-content:center;flex:none}
  .active-list .hn{font-family:var(--mono);font-weight:600}
  .active-list .ev{margin-left:auto;color:var(--muted);font-size:11px}
  .tops{list-style:none;counter-reset:t;display:flex;flex-direction:column;gap:7px}
  .tops li{counter-increment:t;display:flex;align-items:center;gap:8px;font-size:12px;border:1px solid var(--line);border-radius:8px;padding:7px 10px}
  .tops li.none{color:var(--muted);justify-content:center}
  .tops .sev{width:9px;height:9px;border-radius:50%;flex:none}
  .tops .tt{font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .tops .meta{margin-left:auto;font-family:var(--mono);font-size:10.5px;color:var(--muted);flex:none}
  .m365kpi{display:flex;gap:10px}
  .m365kpi .mk{flex:1;border:1px solid var(--line);border-radius:8px;padding:10px 8px;text-align:center}
  .m365kpi .mk b{display:block;font-size:20px;font-weight:800;font-family:var(--mono);line-height:1.1}
  .m365kpi .mk small{color:var(--muted);font-size:10px}
  .m365kpi .mk.warn b{color:var(--amber)}
</style></head><body>
<div class="sheet">
  <header class="head">
    <div class="brand">
      <svg class="mark" viewBox="0 0 40 40" fill="none">
        <path d="M20 2.5 34.7 11v18L20 37.5 5.3 29V11z" fill="#FDECE7" stroke="#F0512E" stroke-width="2.2" stroke-linejoin="round"/>
        <path d="M13.5 20.5l4.4 4.4 8.6-9" stroke="#F0512E" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      <div><h1>HexWatch</h1><div class="tag">SOC gestionado · MDR 24/7</div></div>
    </div>
    <div class="head-row">
      <div>
        <div class="doc-title">Parte de Estado del Servicio</div>
        <div class="doc-sub">Estaciones de trabajo y servidores bajo monitoreo · Cliente <b>${CLIENT}</b></div>
      </div>
      <div class="stamp">
        <span class="shift-pill">${shiftIcon} ${esc(d.turnoLabel)}</span><br>
        ${esc(d.fecha)}<br>
        Corte <b>${esc(d.hora)}</b> · ${esc(d.ventanaLabel)}
      </div>
    </div>
  </header>

  <div class="hero">
    <span class="dot"></span>
    <div><div class="big">${heroBig}</div><div class="small">${heroSub}</div></div>
    <div class="right">Cobertura<br><b>24 / 7 / 365</b></div>
  </div>

  <section>
    <div class="eyebrow">Indicadores del turno</div>
    <div class="kpis">
      <div class="kpi accent">
        <div class="num">${nf(d.totalEndpoints)}</div>
        <div class="lbl">Equipos bajo protección<br>(${nf(d.estaciones)} estaciones · ${nf(d.servidores)} servidores)</div>
        <div class="win">En vigilancia</div>
      </div>
      <div class="kpi">
        <div class="num">${nf(d.eventos12h)}</div>
        <div class="lbl">Eventos de seguridad procesados y correlacionados</div>
        <div class="win">Turno · ${esc(d.ventanaLabel)}</div>
      </div>
      <div class="kpi ${critOk ? 'good' : ''}">
        <div class="num">${nf(d.incidentesCriticos)}</div>
        <div class="lbl">Incidentes críticos${critOk ? '<br>· operación limpia' : ' en atención'}</div>
        <div class="win">Turno · ${esc(d.ventanaLabel)}</div>
        <div class="spark">🛡️</div>
      </div>
      <div class="kpi">
        <div class="num">${nf(d.altaSeveridad30d)}</div>
        <div class="lbl">Amenazas de alta severidad atendidas por el SOC</div>
        <div class="win">Acumulado · 30 días</div>
      </div>
    </div>
  </section>

  <section style="padding-top:2mm">
    <div class="eyebrow">Estado de las estaciones de trabajo · ${nf(d.estaciones)} monitoreadas</div>
    <div class="two">
      <div>
        <div class="bar">
          <span class="seg-on"  style="width:${onPct}%">${d.wkEnLinea}</span>
          <span class="seg-off" style="width:${offPct}%">${d.wkApagadas}</span>
          <span class="seg-att" style="width:${attPct}%">${d.wkAtencion || ''}</span>
        </div>
        <div class="legend">
          <div class="lg"><span class="sw" style="background:var(--green)"></span><div><b>Protegidas y en línea</b><small>Reportando en tiempo real al SOC</small></div><span class="n">${d.wkEnLinea}</span></div>
          <div class="lg"><span class="sw" style="background:var(--slate)"></span><div><b>Apagadas fuera de horario</b><small>Comportamiento normal · sin novedad</small></div><span class="n">${d.wkApagadas}</span></div>
          <div class="lg"><span class="sw" style="background:var(--amber)"></span><div><b>Requieren atención</b><small>En gestión activa por el equipo</small></div><span class="n">${d.wkAtencion}</span></div>
        </div>
      </div>
      <div class="att">
        <h4>En gestión <span class="badge">${d.atencion.length} caso${d.atencion.length === 1 ? '' : 's'}</span></h4>
        <ul>${atencionHtml}</ul>
      </div>
    </div>
    <div class="hosts-grid">
      <div class="hcol">
        <h5>Equipos activos (${d.equiposActivos.length})</h5>
        <div class="chips">${activosHtml}</div>
      </div>
      <div class="hcol">
        <h5>Equipos no activos (${d.equiposInactivos.length})</h5>
        <div class="chips">${inactivosHtml}</div>
      </div>
    </div>
    <div class="active-list">
      <h5>Estaciones más activas del turno</h5>
      <ol>${activasHtml}</ol>
    </div>
  </section>

  <section style="padding-top:0">
    <div class="eyebrow">Resumen de incidentes y amenazas del periodo</div>
    <div class="two">
      <div>
        <h4 style="margin:0 0 9px;font-size:12.5px;font-weight:700">Top 5 incidentes</h4>
        <ol class="tops">${incidentesHtml}</ol>
      </div>
      <div>
        <h4 style="margin:0 0 9px;font-size:12.5px;font-weight:700">Top 5 amenazas detectadas</h4>
        <ol class="tops">${amenazasHtml}</ol>
      </div>
    </div>
  </section>

  ${d.correo.configured ? `<section style="padding-top:0">
    <div class="eyebrow">Microsoft 365 · correo y colaboración</div>
    <div class="two">
      <div>
        <div class="m365kpi">
          <div class="mk"><b>${nf(d.correo.signIns)}</b><small>inicios de sesión</small></div>
          <div class="mk ${d.correo.signInsFailed > 0 ? 'warn' : ''}"><b>${nf(d.correo.signInsFailed)}</b><small>logins fallidos</small></div>
          <div class="mk"><b>${nf(d.correo.usuarios)}</b><small>usuarios activos</small></div>
        </div>
      </div>
      <div>
        <h4 style="margin:0 0 9px;font-size:12.5px;font-weight:700">Riesgos de correo / M365</h4>
        <ol class="tops">${riesgosCorreoHtml}</ol>
      </div>
    </div>
  </section>` : ''}

  <section class="mgmt">
    <div class="eyebrow">Gestión realizada en el turno</div>
    <ul>
      <li><span class="ic">✓</span><div>Monitoreo continuo de <b>${nf(d.totalEndpoints)} endpoints</b> con correlación automática de eventos.</div></li>
      <li><span class="ic">✓</span><div><b>${nf(d.eventos12h)} eventos</b> analizados; <b>${nf(d.incidentesCriticos)}</b> escalaron a incidente crítico.</div></li>
      <li><span class="ic">✓</span><div>Integridad de archivos y accesos vigilados en las estaciones activas.</div></li>
      <li><span class="ic">✓</span><div><b>${d.wkAtencion} estación${d.wkAtencion === 1 ? '' : 'es'}</b> en seguimiento y verificación.</div></li>
      <li><span class="ic">✓</span><div>Respuesta automática ante amenazas <b>armada y operativa</b> (SonicWall).</div></li>
      <li><span class="ic">✓</span><div>Postura de respaldo y parches <b>bajo revisión</b> continua.</div></li>
    </ul>
  </section>

  <footer>
    <div class="sig">Emitido por <b>${ORG}</b> · Centro de Operaciones de Seguridad — para ${CLIENT}</div>
    <div class="next">${proximo}</div>
  </footer>
</div>
</body></html>`;
}
