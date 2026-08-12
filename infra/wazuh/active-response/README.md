# Active Response: fortigate-ban

Respuesta activa de Wazuh/HexWatch que **banea la IP de un atacante en el FortiGate
`FW-GVM`** (cuarentena vía API REST) cuando salta una alerta relevante. Complementa el
`firewall-drop` local de SSH con **bloqueo perimetral** (defensa en profundidad).

## Componentes
- `fortigate-ban.py` — script AR (corre en el **manager**, `location=server`, único host
  que alcanza la API del Forti en `https://192.168.2.1:12443`). Sin secretos embebidos:
  lee el token de `/var/ossec/etc/fortigate.key` (permisos `640 root:wazuh`, **no** se versiona).
- Mecanismo: API de cuarentena `POST /api/v2/monitor/user/banned/add_users`
  (`{ip_addresses, expiry}`) / `clear_users`. El `expiry` (600s) auto-desbanea; además
  el AR usa `timeout` para llamar `delete`.

## Salvaguardas
- **Whitelist dura**: nunca banea rangos internos `10/8, 172.16/12, 192.168/16, 127/8`
  (evita autolockout y bloquear equipos propios).
- Loguea cada acción en `/var/ossec/logs/active-responses.log`.
- Prueba manual: `sudo fortigate-ban.py --test-add <ip>` / `--test-del <ip>`.

## Instalación (en el manager Wazuh)
```bash
install -o root -g wazuh -m 750 fortigate-ban.py /var/ossec/active-response/bin/fortigate-ban.py
# token (no versionado):
umask 077; printf '%s' '<API_KEY>' | sudo tee /var/ossec/etc/fortigate.key >/dev/null
sudo chown root:wazuh /var/ossec/etc/fortigate.key; sudo chmod 640 /var/ossec/etc/fortigate.key
```

## Registro en `ossec.conf`
```xml
<ossec_config>
  <command>
    <name>fortigate-ban</name>
    <executable>fortigate-ban.py</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>
  <active-response>
    <command>fortigate-ban</command>
    <location>server</location>
    <rules_id>5712,81607,81615,81628,81629,44628,44629,81638,44605,44609,44610</rules_id>
    <timeout>600</timeout>
  </active-response>
</ossec_config>
```
Reglas: fuerza bruta SSH (5712), logins/SSL-VPN fallidos del Forti (81607/81615),
ataque IPS detectado/bloqueado (81628/81629), IPS crit/high (44628/44629),
virus (81638) y botnet C&C (44605/44609/44610).
