# Watchdog externo — "el vigilante del vigilante"

Seguro de **último recurso**, independiente de la app y de Wazuh. Si la aplicación
SOC o el propio Wazuh se caen por completo, el panel interno de *Salud del SIEM* no
puede avisar (depende de lo que vigila). Este watchdog cubre ese peor caso.

- Script único en **Python 3 estándar** (sin dependencias): [`siem-watchdog.py`](siem-watchdog.py).
- Hace un **chequeo HTTP** a cada objetivo y, si no responde, envía un **correo SMTP directo**.
- Mantiene estado para **no repetir** el aviso mientras el fallo persista, y avisa la **recuperación**.
- Reintenta cada objetivo (2 reintentos × 5 s) para evitar falsos positivos por blips.

## Vigilancia cruzada (recomendado)

Cada servidor vigila al OTRO, de modo que ninguno depende de sí mismo:

| Corre en | Vigila |
|----------|--------|
| Servidor **Wazuh** (192.168.50.5) | App SOC → `http://192.168.50.4/health` y `/` |
| Servidor **App** (192.168.50.4) | Wazuh API → `https://192.168.50.5:55000` y Indexer `:9200` |

## Instalación (en cada servidor)

```bash
sudo mkdir -p /opt/soc-watchdog /etc/soc-watchdog /var/lib/soc-watchdog
sudo cp siem-watchdog.py /opt/soc-watchdog/
sudo cp watchdog.conf.example /etc/soc-watchdog/watchdog.conf
sudo nano /etc/soc-watchdog/watchdog.conf      # ajustar WATCHDOG_NAME, TARGETS, SMTP_*, ALERT_TO
sudo chmod 600 /etc/soc-watchdog/watchdog.conf # protege la clave SMTP
sudo chmod +x /opt/soc-watchdog/siem-watchdog.py

# Prueba manual
sudo python3 /opt/soc-watchdog/siem-watchdog.py /etc/soc-watchdog/watchdog.conf
```

## Cron (cada 5 minutos)

```bash
sudo crontab -e
# añadir:
*/5 * * * * /usr/bin/python3 /opt/soc-watchdog/siem-watchdog.py /etc/soc-watchdog/watchdog.conf >> /var/log/soc-watchdog.log 2>&1
```

## Diseño (por qué es así)

- **Mínimo de piezas** = más confiable: un archivo, solo stdlib, sin servicios.
- **No depende de la app**: usa su propio SMTP, su propio cron, su propio estado.
- **Liveness real**: un objetivo "responde" si devuelve 200/301/302/401/403; un 502/503/504
  o una conexión rechazada se consideran caída (p. ej. Nginx arriba pero backend caído → 502 → alerta).
- La clave SMTP vive solo en `watchdog.conf` (chmod 600, fuera de git).
