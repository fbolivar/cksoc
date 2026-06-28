# Runbook de Hardening — FortiGate PNNC

> Dispositivo: FortiGate `192.168.50.1` (admin/API `:25443`) · FortiOS **7.6.6**
> Audiencia: equipo de redes / Comité SGSI. Ejecutar en **ventana de mantenimiento** con respaldo de configuración (`execute backup config`).
> Estado a 2026-06-28. **No contiene credenciales.**

---

## 0. Ya aplicado (verificado)
| Ítem | Acción | Estado |
|---|---|---|
| Contraseña admin de la **app SOC** | Cambiada a 20 caracteres aleatorios | ✅ |
| **HTTP de admin en texto claro** (interfaz `SERVIDORES`) | Removido `http` del `allowaccess` (queda `ping https ssh snmp fabric`) | ✅ |

Rollback del HTTP (si fuese necesario):
```
config system interface
  edit "SERVIDORES"
    set allowaccess ping https ssh snmp http fabric
  next
end
```

---

## P1 · LDAP en texto claro → LDAPS  (riesgo: ALTO)

**Hallazgo:** `user ldap "AD:PNNC"` usa `server 192.168.50.2`, `secure disable`, `port 389` → las consultas a AD viajan **sin cifrar**.

**Viabilidad:** ✅ el DC `192.168.50.2` (FQDN `PNNCSRVNCFDC01.PNNC.LOCAL`) ya expone **636/LDAPS** con certificado válido emitido por la CA interna `PNNC-PNNCSRVNCCER01-CA` (vigencia abr-2026 → abr-2027).

**Prerrequisitos (CRÍTICOS — sin esto se rompe la auth):**
1. El certificado del DC es para el **FQDN**, no para la IP (no tiene SAN de IP). Hay que apuntar el LDAP al **FQDN**, no a `192.168.50.2`.
2. El FortiGate debe **resolver** ese FQDN. Hoy su DNS es **público** (`96.45.45.45`, DoT) y **no resuelve `.LOCAL`**. Antes de P1: o bien
   - apuntar el DNS del FortiGate a un DNS interno (el DC), **o**
   - crear una entrada local (`config system dns-database`) `PNNCSRVNCFDC01.pnnc.local → 192.168.50.2`.
3. Importar la CA interna `PNNC-PNNCSRVNCCER01-CA` en el FortiGate (para `server-identity-check`).

**Procedimiento:**
```
# (tras cumplir prerequisitos)
config user ldap
  edit "AD:PNNC"
    set server "PNNCSRVNCFDC01.PNNC.LOCAL"
    set secure ldaps
    set port 636
    set server-identity-check enable
  next
end

# Validar ANTES de confiar en el cambio:
execute ldap-test "AD:PNNC"
```
**Rollback:** `set server 192.168.50.2` / `set secure disable` / `set port 389`.
*Atajo de menor seguridad (cifra sin validar cert): `set secure ldaps` + `set server-identity-check disable`.*

---

## Ruido NTLM (regla Wazuh 92657) — causa raíz y opciones

**Causa raíz:** el **FSSO agentless polling** (`user fsso-polling id=1`, `server 192.168.50.2`, cuenta `pnnc\pnncnc`) sondea los logs del DC **por IP**; al no haber SPN para una IP, Windows **cae a NTLM**.

**Importante:** este NTLM **ya está silenciado en Wazuh** (regla 92657 excluida para `pnncnc`) → es **benigno**. No es urgente.

### Opción A · Reinstalar el Collector Agent y apagar el polling (arquitectura limpia)
**Contexto:** el `user fsso "PNNC_PPAL"` (→ `192.168.50.2:8000`) figura **disconnected** porque el FSSO Collector Agent (FSAE) **fue desinstalado del DC ~21-may-2025** (solo quedan logs huérfanos en `C:\Program Files (x86)\Fortinet\FSAE\`, sin binarios ni servicio). Por eso restaurarlo es una **reinstalación**, no un "reiniciar servicio".

Pasos (en el DC `PNNCSRVNCFDC01`):
1. Descargar el **FSSO Agent** compatible con FortiOS 7.6 desde el portal de soporte de Fortinet.
2. Limpiar el remanente: respaldar y borrar `C:\Program Files (x86)\Fortinet\FSAE\` (logs viejos, ~122 MB).
3. Instalar el **Collector Agent** en **modo DC Agent** (lee los eventos de logon localmente; **sin NTLM remoto**). El instalador despliega el `dcagent.dll` en los DCs.
4. En la consola "Configure Fortinet Single Sign-On Agent": fijar el **puerto de escucha 8000**, autorizar el FortiGate `192.168.50.1` y definir la **clave precompartida** (la misma que en el FortiGate para `PNNC_PPAL`).
5. Abrir en el firewall de Windows del DC el **TCP 8000 de entrada** desde `192.168.50.1`.
6. Verificar en el FortiGate que `PNNC_PPAL` pasa a **connected** y `Show Logon Users` lista usuarios.
7. **Solo entonces** desactivar el polling:
   ```
   config user fsso-polling
     edit 1
       set status disable
     next
   end
   ```

### Opción B · Forzar Kerberos en el polling (más simple, pero requiere DNS)
Cambiar el `server` del polling de IP a **FQDN** para que `pnncnc` negocie Kerberos:
```
config user fsso-polling
  edit 1
    set server "PNNCSRVNCFDC01.PNNC.LOCAL"
  next
end
```
**Bloqueo actual:** igual que P1, el DNS público del FortiGate **no resuelve el FQDN**. Requiere primero DNS interno o `dns-database`. **Rollback:** `set server 192.168.50.2`.

---

## P3 · 2FA en cuentas super-admin  (riesgo: BAJO-MEDIO)
Cuentas `super_admin` sin 2FA: `admin`, `ecomil`, `emerson.cruz`, `fernando.bolivar` (todas con *trusthosts* restringidos ✅).
- Provisionar **FortiToken** (móvil) o **email OTP** por cuenta. No bloquearse: probar con una cuenta antes de aplicarlo a todas.
- Recomendado además: deshabilitar/renombrar la cuenta `admin` por defecto y dejar una cuenta nominal *break-glass*.

---

## P5 · SNMP  (riesgo: BAJO)
`SERVIDORES` y `LACP_LAN_PNNC` permiten `snmp` en `allowaccess`.
- Confirmar que sea **SNMP v3** (auth+priv) y **deshabilitar v1/v2c**.
```
config system snmp community   # si hay comunidades v1/v2c -> revisar/eliminar
  ...
config system snmp user        # v3 con auth-proto sha256 y priv-proto aes256
  ...
```

---

## Opcional · cosmético
- Eliminar el `user fsso "PNNC_PPAL"` fantasma del FortiGate para que no figure siempre "disconnected" — **solo si no se va a reinstalar el agente** (al borrarlo se pierde su configuración/clave). Mientras se planee la Opción A, **conviene conservarlo**.

---

## Prioridad sugerida
1. (hecho) Contraseña admin + quitar HTTP cleartext.
2. **2FA en super-admins** (alto valor, bajo riesgo).
3. **P1 LDAPS** — tras arreglar el DNS del FortiGate.
4. **FSSO**: dejar como está (NTLM benigno) o ejecutar Opción A en un proyecto.
5. SNMP v3.
