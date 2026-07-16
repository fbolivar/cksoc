# Plan de operacionalización del SOC — PNNC

> Objetivo: pasar de "tener las funcionalidades" a **operarlas**. Basado en el
> panorama real de alertas de PNNC (últimos 7 días), no en plantillas genéricas.

## 1. Panorama real (de qué se alimenta el plan)

Señales de mayor severidad observadas (nivel ≥ 10, 7 días):

| Volumen | Nivel | Regla | Qué es | Automatizar? |
|---|---|---|---|---|
| 487.704 | 10 | 100020 | FortiGate: posible escaneo de puertos (T1046) | ❌ NO — ruido, muy probablemente escáneres internos/monitoreo |
| 27.287 | 10 | 100011 | Volumen anómalo de tráfico denegado | ❌ NO — informativo |
| 1.652 | **15** | 92213 | Ejecutable soltado en carpeta usada por malware (T1105) — host FFS02/.35 | ✅ Incidente + notificar |
| 256 | 10 | 61110 | Múltiples errores de sistema Windows | ❌ operacional |
| 67 | 10 | 23505 | CVE-2024-7592 (Python) | → gestión de vulnerabilidades |
| 8 | **14** | 91823 | PowerShell usó `Invoke-command` para ejecutar | ✅ Incidente + notificar |
| 7 | **12** | 61627 | Sysmon: lsass.exe como *parent* (posible acceso a credenciales) | ✅ Incidente + notificar |
| 1 | 10 | 100031 | Fuerza bruta IPsec XAuth desde IP externa (186.86.110.248) | ✅ **Bloquear IP** + notificar |
| 1 | **12** | 100202 | AD CRÍTICO: `pnncnc` agregó CN=test.soc a Users | ✅ Incidente + notificar |

> ⚠️ **Observación para verificar:** la cuenta `pnncnc` creó un usuario `test.soc` en AD (regla 100202). Confirmar si fue una prueba autorizada.

**Regla de oro:** el escaneo de puertos (100020) domina el volumen (487k) y NO debe automatizarse — un auto-bloqueo ahí sería peligroso y ruidoso. Automatizar solo señales **específicas y accionables**.

---

## 2. Playbooks iniciales sugeridos (SOAR)

**Todos arrancan en `Simulación` y deshabilitados.** Se observan 3-5 días, se revisa el historial de ejecuciones, y solo entonces se pasan a `Activo`.

### P1 — Bloqueo de fuerza bruta externa 🔴 (el de mayor valor)
- **Condición:** reglas `100031` (o nivel ≥ 10 + grupo `fortigate` con IP de origen pública).
- **Acciones:** `block_ip` + `notify`.
- **Cooldown:** 60 min. **Modo objetivo:** Activo (tras validar).
- Por qué: IP externa atacando = el caso SOAR clásico y seguro (la lista blanca protege lo interno).

### P2 — Malware soltado en disco 🔴
- **Condición:** regla `92213` (nivel 15).
- **Acciones:** `create_incident` + `notify`. (NO bloquear: es endpoint, no IP.)
- **Cooldown:** 30 min.
- Por qué: L15 en FFS02/.35 (el host con FortiClient vulnerable) — merece caso formal inmediato.

### P3 — Cambios críticos en Active Directory 🟠
- **Condición:** regla `100202` (o grupo `policy_changed` nivel ≥ 12).
- **Acciones:** `create_incident` + `notify`.
- **Cooldown:** 15 min.
- Por qué: creación/modificación de cuentas privilegiadas = alto impacto, trazar siempre.

### P4 — Ejecución sospechosa / acceso a credenciales 🟠
- **Condición:** reglas `91823`, `61627` (o MITRE `T1059.001`, nivel ≥ 12).
- **Acciones:** `create_incident` + `notify`.
- **Cooldown:** 30 min.

> **Explícitamente sin playbook:** escaneo de puertos (100020) y burst de denegados (100011) — ruido de red, se revisan por tendencia, no por acción automática.

**Ruta de adopción de cada playbook:** Simulación → revisar `Ejecuciones recientes` 3-5 días → ¿haría lo correcto? → Activo. Empezar por P2/P3/P4 (solo crean incidente/notifican, riesgo nulo) y dejar **P1 (auto-bloqueo) de último**, tras total confianza.

---

## 3. Biblioteca de cacerías guardadas (Threat Hunting)

Guardar estas búsquedas; marcar con alerta ✅ las de mayor criticidad (avisan por la campanita al superar umbral).

| Cacería | Filtros | Alerta | Umbral |
|---|---|---|---|
| **Malware soltado** | regla `92213`, 24h | ✅ | 1 |
| **Cambios en AD** | grupo/regla `100202`, nivel ≥ 12, 24h | ✅ | 1 |
| **PowerShell sospechoso** | regla `91823` / MITRE `T1059.001`, 24h | ✅ | 1 |
| **Acceso a credenciales (lsass)** | regla `61627`, 7d | ✅ | 1 |
| **Fuerza bruta** | regla `100031` / grupo brute, 24h | ✅ | 1 |
| **Movimiento lateral / RDP** | MITRE `T1021.006`, 7d | — | — |
| **Creación de cuentas** | MITRE `T1136`, 7d | ✅ | 1 |
| **Foco host vulnerable** | agente `PNNCSRVNCFFS02`, nivel ≥ 8, 24h | — | — |
| **Críticas globales** | nivel ≥ 12, 24h | ✅ | 5 |

> Cómo: en *Threat Hunting*, arma la búsqueda con los filtros, clic en **Guardar**, ponle nombre y activa la alerta cuando corresponda.

---

## 4. SLAs (matriz + cadencia)

Objetivos por severidad (los que ya trae la página de Métricas; ajustar con el equipo):

| Severidad | Respuesta (1ª acción) | Resolución |
|---|---|---|
| Crítica | 30 min | 4 h |
| Alta | 1 h | 8 h |
| Media | 4 h | 24 h |
| Baja | 8 h | 72 h |

**Cadencia operativa recomendada:**
- **Diario:** revisar Métricas SOC (backlog, incidentes > 24h) + la campanita. Cerrar/actualizar incidentes.
- **Semanal:** revisar cumplimiento de SLA (página Métricas), ajustar playbooks/cacerías según lo que disparó, revisar Auditoría (accesos, fallidos).
- **Mensual:** tendencia MTTD/MTTR, revisión de la imagen base de servidores y del avance de hardening CIS.

**Cómo se mide:** la app ya calcula MTTD/MTTA/MTTR y % de SLA sobre los incidentes. Para que MTTD tenga dato, **escalar los incidentes desde una alerta** (el botón en Alertas guarda el tiempo de la alerta).

---

## 5. Plan de adopción por fases

- **Semana 1 — Medir y cazar:** guardar las 9 cacerías; empezar a escalar alertas → incidentes; revisar Métricas a diario para tener línea base de MTTR/SLA.
- **Semana 2 — Playbooks en simulación:** crear P1-P4 en simulación; revisar el historial de ejecuciones.
- **Semana 3 — Activar lo seguro:** pasar P2/P3/P4 (crean incidente/notifican) a Activo. P1 sigue en simulación.
- **Semana 4 — Auto-respuesta:** con confianza en el historial, pasar P1 (auto-bloqueo) a Activo. Revisar SLA de la primera semana operando.

**Paralelo (no es de la app, pero mueve la aguja):** cerrar backups off-server, 2FA en admin/analista, cert por GPO, y la remediación de FortiClient/CIS (incidentes abiertos).
